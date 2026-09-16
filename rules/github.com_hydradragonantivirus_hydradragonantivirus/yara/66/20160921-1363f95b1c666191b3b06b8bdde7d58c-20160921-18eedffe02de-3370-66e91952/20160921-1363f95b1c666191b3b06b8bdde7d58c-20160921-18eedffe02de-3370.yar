rule _20160921_1363f95b1c666191b3b06b8bdde7d58c_20160921_18eedffe02de_3370 {
  meta:
    description = "datamaliciousorder - from files 20160921_1363f95b1c666191b3b06b8bdde7d58c.js, 20160921_18eedffe02de43ba2ee494451deba790.js, 20160921_1e5a9eb0eb0b79e733771c60a3c09d60.js, 20160921_46f76411edda6b812c8adc67d2ad383c.js, 20160921_bd4d87f94769a02253ed6ac2e747557f.js, 20160921_dcd6ef8585af301daafce3419ba14724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa3f648dc04a8b93f29d34ed8ee56d888b7b7469f9b81a0cc95a1d6f7ab8b098"
    hash2       = "295460c559aa147e2ea748501c56677647c72b71ee7df9051801008304580029"
    hash3       = "fb9f71807b6b8b0f0dea01eb8e6e4eef0c54c22c99493c5825b4acb828c2e8b1"
    hash4       = "f72be114af5c43c1d1df32b679c547b8e87512e78385118e9bcd668bc660230a"
    hash5       = "de567d209b0d4353173c2f3ae63037edd6f5695cc5edcdba1dba29b422d963ac"
    hash6       = "599a5b97cea2145a98305cb09031a146a6d64c54509328df8783368c3a3ba008"

  strings:
    $s1 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retu" ascii
    $s2 = "\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function " ascii
    $s3 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s5 = "urn \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(" ascii
    $s6 = "ck(){return \"Jo\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}