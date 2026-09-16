rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_5031 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_5f14ae6f169c53d6d49523d1e13e4ab9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "270eb53363684986d2aef11b6b5bb4cd5c5cb316f626e41b627db2cf899b440e"

  strings:
    $s1 = " \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s2 = "Pu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s3 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){r" ascii
    $s4 = "function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){ret" ascii
    $s5 = "fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IK" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}