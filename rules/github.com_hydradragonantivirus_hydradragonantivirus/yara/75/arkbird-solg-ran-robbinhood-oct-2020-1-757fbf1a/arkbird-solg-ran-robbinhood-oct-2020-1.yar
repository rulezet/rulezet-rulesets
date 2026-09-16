rule ARKBIRD_SOLG_Ran_Robbinhood_Oct_2020_1: FILE {
  meta:
    description = "Detect RobbinHood ransomware"
    author      = "Arkbird_SOLG"
    id          = "adaacb06-0738-5d2b-b97e-b9007341f743"
    date        = "2020-11-04"
    modified    = "2020-11-05"
    reference   = "https://twitter.com/joakimkennedy/status/1323957238680178689"
    source_url  = "https://github.com/StrangerealIntel/DailyIOC/blob/a873ff1298c43705e9c67286f3014f4300dd04f7/2020-11-05/RobbinHood/Ran_RobbinHood_Oct_2020_1.yar#L1-L20"
    license_url = "N/A"
    logic_hash  = "72d0e9b1e2f6aee8f24125e6e6801329e2fad016f05a94ad65c04874a016d09d"
    score       = 75
    quality     = 67
    tags        = "FILE"
    hash1       = "7c7ef3ab31ab91a7379bc2e3f32473dfa7adf662d0c640ef994103f6022a092b"
    hash2       = "f927dd9044d7fa874dc6b98a0f5c9c647f3a9e5393bfe034b425cbf8db93e501"
    hash2       = "3f56501f764d49723188bb119845fec4f2419a5080b74513fd0734e2a628e754"

  strings:
    $seq  = " !=  <== as  at  fp= is  lr: of  on  pc= sp: sp=%v\r\n) = ) m=+Inf, n -Inf.bat.cmd.com.exe/PID10603125: p=ACDTACSTAEDTAESTAKDTAKSTAWSTAhomAtoiCESTChamDashEESTGOGCJulyJuneLisuM2RtM2RzM2ZyM2cyM2dwM3ByMiaoModiN3o=NZDTNZSTNewaNjAyQVJDQVZQSASTStatTU1TThaiTkVGUFBUWESTWExTY210Y21kY25mY2FiY2FzY2M=Y2R4Y2RmY2RyY2UxY2UyY2VyY2ZnY2ZwY2ZyY2dtY2htY2liY2xzY3BpY3BwY3IyY3J0Y3J3Y3M=Y3N2Y3NoY3NsY3NyY3NzY3RmYW9pYWFjYWI0YWJrYWN0YWNoYWNwYWNyYWRiYWRpYWRwYWRzYWVzYWk=YWl0YWlmYWpsYWw=YXBqYXBrYXJ3YXN0YXN4YXNjYXNmYXNtYXNwYXZpYXdnYm1wYmF0YmF5YmFjYmFrYmFyYmM2YmM3YmNvYmRiYmZmYmd0YmlnYmlrYmluYmt6YmtmYmtwYnB3YnJkYnNhYnVwYnoyYw==Z28=Z2FtZ2RiZ2hvZ2lmZ3BnZ3J5Z3o=ZG1wZG5nZG90ZG9jZGF0ZGFjZGFzZGI=ZGIwZGIzZGJ4ZGJhZGJmZGMyZGNoZGNyZGNzZGRkZGRzZGVtZGVyZGVzZGZzZGdjZGl0ZGlmZGltZGlwZGlyZGp2ZHJ3ZHJmZHN0ZHNiZHNrZHRkZHdmZHdnZHdzZHh0ZHh4ZHhiZHhmZHhnZW1sZWRiZXBrZXBzZXJmZXNtZXhmZm1iZm9zZmJ3ZmRiZmY=ZmZkZmZmZmg=ZmhkZmx2ZmxhZmxmZnB4ZnBrZnJtZnNoZnVsZnhn\n\tm=]"
    $com1 = "os/exec.(*Cmd).Run" fullword ascii
    $com2 = "os/exec.(*Cmd).Start" fullword ascii
    $com3 = "C:\\windows\\temp\\s1.vbsC:\\windows\\temp\\s2.vbsC"
    $str1 = "cmdzczNhcs"
    $str2 = "Y21kLmV4ZSAvYyBiY2RlZGl0LmV4ZSAvc2V0IHtkZWZhdWx0fSBib290c3RhdHVzcG9saWN5IGlnbm9yZWFsbGZhaWx1cmVz"
    $str3 = "Y21kLmV4ZSAvYyBiY2RlZGl0LmV4ZSAvc2V0IHtkZWZhdWx0fSByZWNvdmVyeWVuYWJsZWQgbm8="

  condition:
    uint16(0) == 0x5a4d and filesize > 600KB and $seq and 2 of ($com*) and 2 of ($str*)
}