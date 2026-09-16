rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_5029 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_5831ee10eea30ef3b8363cda03eba31a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"

  strings:
    $s1 = "on fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"B" ascii
    $s2 = "{return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3 = "{return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})" ascii
    $s4 = "f\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s5 = "k(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Za\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}