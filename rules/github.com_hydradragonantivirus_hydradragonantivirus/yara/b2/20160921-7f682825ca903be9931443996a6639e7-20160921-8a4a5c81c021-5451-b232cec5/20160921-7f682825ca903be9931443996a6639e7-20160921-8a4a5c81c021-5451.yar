rule _20160921_7f682825ca903be9931443996a6639e7_20160921_8a4a5c81c021_5451 {
  meta:
    description = "datamaliciousorder - from files 20160921_7f682825ca903be9931443996a6639e7.js, 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js, 20160921_f80c41f35464b4c1cc71c3a8431a6e96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0702db471409264d1d764fadd3401cdedc4b3ca7166d99d61893fad5007d7f03"
    hash2       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash3       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"
    hash4       = "8186d069d8ec2c8754bba46343500f71eff6d1d47a5ecb2ca82a097bf5b41dc3"

  strings:
    $s1 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"" ascii
    $s2 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){r" ascii
    $s3 = "(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s4 = "{return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";}" ascii
    $s5 = "){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}