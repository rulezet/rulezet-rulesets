rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_d97203a3a0e9_1568 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1  = ";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fu" ascii
    $s2  = "n \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(fun" ascii
    $s3  = "ck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";" ascii
    $s4  = "urn \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(" ascii
    $s5  = "n \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s6  = " fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"H" ascii
    $s7  = "(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){r" ascii
    $s8  = " fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AD" ascii
    $s9  = "n \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s10 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retu" ascii
    $s11 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return " ascii
    $s12 = "tion fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}