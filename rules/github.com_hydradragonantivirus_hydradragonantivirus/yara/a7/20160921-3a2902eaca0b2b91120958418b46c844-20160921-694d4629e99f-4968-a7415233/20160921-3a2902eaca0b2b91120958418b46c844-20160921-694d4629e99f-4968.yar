rule _20160921_3a2902eaca0b2b91120958418b46c844_20160921_694d4629e99f_4968 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_694d4629e99fd1d23d60bc73e0e28e30.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash2       = "01147c2f2f43df58f5a1b60481a04add7d73eba030abaeed3f9dedb1fd3574e4"

  strings:
    $s1 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"KVh\";})(),(function fu" ascii
    $s2 = "ction fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s3 = "return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s4 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s5 = "w\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xw\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}