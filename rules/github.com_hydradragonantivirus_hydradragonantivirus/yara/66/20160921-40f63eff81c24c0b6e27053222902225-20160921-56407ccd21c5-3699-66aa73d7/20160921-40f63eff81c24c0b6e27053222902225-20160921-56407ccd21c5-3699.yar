rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_3699 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){" ascii
    $s2 = "rn \"XCr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s3 = " fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"" ascii
    $s4 = "n fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s5 = "),(function fuck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(" ascii
    $s6 = "\"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Xw\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}