rule _20160921_7c37cf57d8ed1c10fea15c60dc79c0c8_20160921_832521e32124_5436 {
  meta:
    description = "datamaliciousorder - from files 20160921_7c37cf57d8ed1c10fea15c60dc79c0c8.js, 20160921_832521e32124647e5f9543472346f319.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3acecff4ec35ade7d618cbd511372d6023de7d591317c5e6ce95fc088b8cf6e"
    hash2       = "7d8db496c31215a3730a6ed92a0e2b36ff0fe0e9ddaf7405680d1002474263e1"
    hash3       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1 = "on fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s2 = "function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){re" ascii
    $s3 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s4 = "k(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";" ascii
    $s5 = "})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}