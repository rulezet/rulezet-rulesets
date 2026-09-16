rule _20160921_d905978b34bea5948e843dd7ecb9dc6e_20160921_fec97a223836_5713 {
  meta:
    description = "datamaliciousorder - from files 20160921_d905978b34bea5948e843dd7ecb9dc6e.js, 20160921_fec97a223836973c5d09ac6d41b2ad43.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"
    hash2       = "d8c26b92e119ca52cb4c0aa43351cde4400c3d6abac819e57a391628e14280cb"

  strings:
    $s1 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s2 = "urn \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s3 = "ion fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s4 = "return \"Xw\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5 = "urn \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}