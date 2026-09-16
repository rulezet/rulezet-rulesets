rule _20160921_469953d9833167e141d9f086f1f41437_20160921_c0cd20cf50e8_2924 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"

  strings:
    $s1 = "{return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"GNm\";})" ascii
    $s2 = "n fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"E" ascii
    $s3 = "k(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\"" ascii
    $s4 = "\"Cd\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(func" ascii
    $s5 = "h\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s6 = ",(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){r" ascii
    $s7 = "turn \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}