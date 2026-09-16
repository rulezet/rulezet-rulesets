rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_5c9dd9a0e8a8_4340 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js, 20160921_69a85efe2b4b34254269f0f82213bf2c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"
    hash3       = "8def27dca1738a7df5978549903a2c809fcb8a8d158e5de122afc54ad2dd3dea"

  strings:
    $s1 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s2 = "on fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s3 = "})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Py\";})(),(function fuck" ascii
    $s4 = "){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Fv\";}" ascii
    $s5 = "eturn \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}