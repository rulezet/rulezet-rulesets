rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_5645898a54df_274 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_5645898a54dfcbd78b32ee6da656f545.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "0d8d12c1edd9af4fca97f4e7013b538499acfb96d7d0bed0a7b5419e888829b1"
    hash3       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"

  strings:
    $s1  = "urn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s2  = "o\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s3  = "urn \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})()," ascii
    $s4  = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s5  = "ion fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return" ascii
    $s6  = "fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"I" ascii
    $s7  = " fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Wo" ascii
    $s8  = "return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})()" ascii
    $s9  = "(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\"" ascii
    $s10 = "fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd" ascii
    $s11 = "urn \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s12 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"" ascii
    $s13 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s14 = "uck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"Ug" ascii
    $s15 = "{return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(" ascii
    $s16 = "return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s17 = "(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";" ascii
    $s18 = "{return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";}" ascii
    $s19 = "rn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(f" ascii
    $s20 = "})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}