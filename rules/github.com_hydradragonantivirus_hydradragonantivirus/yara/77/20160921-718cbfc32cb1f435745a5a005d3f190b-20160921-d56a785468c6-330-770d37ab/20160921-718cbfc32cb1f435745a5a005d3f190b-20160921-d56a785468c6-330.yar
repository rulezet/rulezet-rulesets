rule _20160921_718cbfc32cb1f435745a5a005d3f190b_20160921_d56a785468c6_330 {
  meta:
    description = "datamaliciousorder - from files 20160921_718cbfc32cb1f435745a5a005d3f190b.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"
    hash2       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1  = "(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck" ascii
    $s2  = "on fuck(){return \"Ve\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3  = "\"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(functio" ascii
    $s4  = "(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\"" ascii
    $s5  = "k(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"We\"" ascii
    $s6  = "urn \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(" ascii
    $s7  = "{return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s8  = "turn \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(" ascii
    $s9  = "){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})" ascii
    $s10 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s11 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck" ascii
    $s12 = "urn \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s13 = "urn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"PDf\";})(),(f" ascii
    $s14 = "k(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo" ascii
    $s15 = "})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s16 = " fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DR" ascii
    $s17 = "n fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"P" ascii
    $s18 = "\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function " ascii
    $s19 = "ck(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s20 = "rn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}