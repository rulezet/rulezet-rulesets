rule _20160921_8a4a5c81c02126f78061e6b947b8f9bc_20160921_920f820521e7_3077 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_920f820521e7af7d81b11e9545080390.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash2       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"
    hash3       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"

  strings:
    $s1 = "(function fuck(){return \"Cd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){ret" ascii
    $s2 = ",(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){" ascii
    $s3 = "){return \"DAa\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";" ascii
    $s4 = "return \"OQr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s5 = " \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(fu" ascii
    $s6 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"N" ascii
    $s7 = "(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}