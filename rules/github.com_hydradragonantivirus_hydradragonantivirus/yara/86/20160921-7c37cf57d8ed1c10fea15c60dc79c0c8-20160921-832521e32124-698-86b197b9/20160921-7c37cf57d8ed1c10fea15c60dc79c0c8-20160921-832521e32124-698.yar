rule _20160921_7c37cf57d8ed1c10fea15c60dc79c0c8_20160921_832521e32124_698 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash2       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash3       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1  = "unction fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retu" ascii
    $s2  = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3  = "LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(funct" ascii
    $s4  = "{return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s5  = "return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})()" ascii
    $s6  = "urn \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s7  = "return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(" ascii
    $s8  = ")(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck" ascii
    $s9  = "return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s10 = "function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){re" ascii
    $s11 = " \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ar\";})(),(func" ascii
    $s12 = " fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s13 = "turn \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s14 = "ck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Oh\"" ascii
    $s15 = "k(){return \"DAa\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\"" ascii
    $s16 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){retur" ascii
    $s17 = "nction fuck(){return \"XHj\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s18 = "tion fuck(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s19 = "return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Av\";})(" ascii
    $s20 = "nction fuck(){return \"ZLd\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}