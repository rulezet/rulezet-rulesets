rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_d7a1651fca71_3626 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"

  strings:
    $s1 = "n \"Av\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s2 = "ction fuck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Py\";})()" ascii
    $s4 = "(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){re" ascii
    $s5 = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ve\";})(),(function fuck()" ascii
    $s6 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}