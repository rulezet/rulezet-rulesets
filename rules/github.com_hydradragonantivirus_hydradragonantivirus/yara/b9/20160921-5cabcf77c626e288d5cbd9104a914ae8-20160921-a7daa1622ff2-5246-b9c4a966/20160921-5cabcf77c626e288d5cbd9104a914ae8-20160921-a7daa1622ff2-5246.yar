rule _20160921_5cabcf77c626e288d5cbd9104a914ae8_20160921_a7daa1622ff2_5246 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cabcf77c626e288d5cbd9104a914ae8.js, 20160921_a7daa1622ff2bc3dccfc20f622902f7b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"
    hash2       = "4caa07134c114c6f14592ae1a6f87a08bd21b6048c96d44b5eb70d9762008059"

  strings:
    $s1 = "unction fuck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retur" ascii
    $s2 = "fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MU" ascii
    $s3 = "ion fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s4 = "turn \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s5 = "ck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}