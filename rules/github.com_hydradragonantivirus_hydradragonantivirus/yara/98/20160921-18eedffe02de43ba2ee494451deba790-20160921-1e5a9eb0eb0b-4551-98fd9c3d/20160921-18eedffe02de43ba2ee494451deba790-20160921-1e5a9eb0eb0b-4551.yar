rule _20160921_18eedffe02de43ba2ee494451deba790_20160921_1e5a9eb0eb0b_4551 {
  meta:
    description = "datamaliciousorder - from files 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_fc08be0621d4ffbced0eaca2b2622b07.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash2       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash3       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash4       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash5       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash6       = "1641412d2cba74b5cd1b4c4619c995601c42039d472339eb7cb10d97e1d47339"

  strings:
    $s1 = "n \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s2 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s3 = "n \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s4 = ",(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s5 = "(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}