rule _20160921_18eedffe02de43ba2ee494451deba790_20160921_1e5a9eb0eb0b_4552 {
  meta:
    description = "datamaliciousorder - from files 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash2       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash3       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash4       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "\"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(funct" ascii
    $s2 = "n \"Zy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})(),(fun" ascii
    $s3 = "fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CC" ascii
    $s4 = "TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(functio" ascii
    $s5 = "),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}