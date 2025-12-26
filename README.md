# WeChat Database Decryptor

WeChat(위챗) 암호화된 데이터베이스를 복호화하는 도구입니다.
2025.12.26 update

## 기능

- WeChat 앱 데이터에서 암호화 키 자동 추출
- WCDB(WeChat Database) 암호화 해제
- SQLite 데이터베이스로 변환

## 요구사항

```bash
Python 3.7+
```

## 설치

```bash
git clone https://github.com/yourusername/wechat-db-decryptor.git
cd wechat-db-decryptor
pip install -r requirements.txt
```

## 사용법

### 기본 사용 (자동)

WeChat 폴더만 지정하면 자동으로 DB를 찾아서 키를 추출하고 복호화합니다:

```bash
python wechat_decrypt.py /path/to/com.tencent.mm
```

또는 DB 파일을 직접 지정:

```bash
python wechat_decrypt.py /path/to/com.tencent.mm /path/to/EnMicroMsg.db
```

### 옵션

```bash
# 출력 파일명 지정
python wechat_decrypt.py /path/to/com.tencent.mm -o output.db

# 모든 가능한 키 시도
python wechat_decrypt.py /path/to/com.tencent.mm --try-all

# 특정 사용자 ID 지정
python wechat_decrypt.py /path/to/com.tencent.mm --user-id abc123def456

# 키만 추출
python wechat_decrypt.py /path/to/com.tencent.mm --extract-key-only

# 이미 알고 있는 키로 복호화
python wechat_decrypt.py /path/to/EnMicroMsg.db --key 1277f69

# 조용히 실행 (상세 로그 숨김)
python wechat_decrypt.py /path/to/com.tencent.mm --quiet
```

## 프로젝트 구조

```
wechat-db-decryptor/
├── README.md              # 문서
├── requirements.txt       # Python 패키지
├── wechat_decrypt.py      # 메인 스크립트 
└── .gitignore
```

## 작동 원리

1. **키 추출**: WeChat 앱 데이터에서 IMEI와 UIN을 추출하여 MD5 해시로 암호화 키 생성
2. **데이터베이스 복호화**: PBKDF2-HMAC-SHA1로 키를 유도하고 AES-CBC로 각 페이지 복호화
3. **SQLite 변환**: 복호화된 데이터를 표준 SQLite 형식으로 저장

## 예제

```bash
# 가장 간단한 사용법 (자동으로 DB 찾기)
python wechat_decrypt.py ./com.tencent.mm

# 여러 키 시도
python wechat_decrypt.py ./com.tencent.mm --try-all -o decrypted.db

# 특정 사용자 ID의 DB만 복호화
python wechat_decrypt.py ./com.tencent.mm --user-id abc123def456

# 키만 먼저 확인
python wechat_decrypt.py ./com.tencent.mm --extract-key-only
# 출력: Key: 1277f69

# 그 키로 복호화
python wechat_decrypt.py ./EnMicroMsg.db --key 1234567
```

## 주의사항

- 이 도구는 **교육 및 연구 목적**으로만 사용하세요
- 자신의 데이터에만 사용하세요
- 타인의 개인정보 침해는 법적 책임을 수반합니다

