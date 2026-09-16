rule _20160921_3a2902eaca0b2b91120958418b46c844_20160921_7e15ac275536_3660 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_7e15ac2755366d4644a83de8ec9c1a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash2       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"

  strings:
    $s1 = "urn \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s2 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s3 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s4 = "rn \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5 = "\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s6 = "){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}