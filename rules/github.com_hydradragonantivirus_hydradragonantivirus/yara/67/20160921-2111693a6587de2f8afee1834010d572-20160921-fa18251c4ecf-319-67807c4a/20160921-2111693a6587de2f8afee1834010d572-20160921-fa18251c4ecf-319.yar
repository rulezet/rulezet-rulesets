rule _20160921_2111693a6587de2f8afee1834010d572_20160921_fa18251c4ecf_319 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_fa18251c4ecf88527d80b62724da7b36.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "21b811f7ccb44c8d67ee516b8cfe4393b6e248d9db38cab4200e9794e3da737f"

  strings:
    $s1  = "eturn \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s2  = "unction fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii
    $s3  = "})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck" ascii
    $s4  = "){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";}" ascii
    $s5  = "fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IK" ascii
    $s6  = "return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})" ascii
    $s7  = "\"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s8  = "urn \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s9  = "rn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(f" ascii
    $s10 = "ck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s11 = "(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\"" ascii
    $s12 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii
    $s13 = "fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu" ascii
    $s14 = "(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){re" ascii
    $s15 = "p\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s16 = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s17 = "return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})" ascii
    $s18 = "g\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function " ascii
    $s19 = "(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";}" ascii
    $s20 = "ck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}