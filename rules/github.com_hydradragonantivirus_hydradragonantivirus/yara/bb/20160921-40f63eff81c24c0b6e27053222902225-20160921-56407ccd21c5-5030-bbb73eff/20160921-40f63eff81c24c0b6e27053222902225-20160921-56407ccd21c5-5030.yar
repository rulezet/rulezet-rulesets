rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_5030 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"
    hash3       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "unction fuck(){return \"XHj\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Py\";})(),(function fuck(){retu" ascii
    $s2 = " \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii
    $s3 = "ction fuck(){return \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return" ascii
    $s4 = "Nm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s5 = "n \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}