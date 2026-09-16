rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_c01f87df9de4_276 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_c01f87df9de4ce5ca88bd5f8e99b8421.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "863f188b1216c3a7a1dc561983400a4e8b6fadded702cf47ee8533061495abc8"

  strings:
    $s1  = " fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf" ascii
    $s2  = "turn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(" ascii
    $s3  = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s4  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s5  = "fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IK" ascii
    $s6  = "})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fu" ascii
    $s7  = "\"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s8  = "(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck" ascii
    $s9  = "){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";" ascii
    $s10 = "k(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";" ascii
    $s11 = "function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s12 = "on fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return " ascii
    $s13 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb" ascii
    $s14 = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";" ascii
    $s15 = "i\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function" ascii
    $s16 = ")(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s17 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return" ascii
    $s18 = "on fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s19 = "(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";" ascii
    $s20 = "ck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}