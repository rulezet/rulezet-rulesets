rule _20160921_5d253f3fb31881c7c27141d74e02cacb_20160921_7e2de7c26f13_730 {
  meta:
    description = "datamaliciousorder - from files 20160921_5d253f3fb31881c7c27141d74e02cacb.js, 20160921_7e2de7c26f136a1a958818752613cac3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"
    hash2       = "540bec3c8538992ab2a631157eae2d03acb2afd24ba0842fcdbbcd7a792913b3"

  strings:
    $s1  = "o\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Qh\";})(),(function " ascii
    $s2  = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(functio" ascii
    $s3  = "rn \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Sx\";})(),(fu" ascii
    $s4  = "ion fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return " ascii
    $s5  = "turn \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s6  = "function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){re" ascii
    $s7  = "MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(functi" ascii
    $s8  = "n fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s9  = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s10 = " fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Yk" ascii
    $s11 = "turn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(" ascii
    $s12 = "w\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function f" ascii
    $s13 = "urn \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(" ascii
    $s14 = ",(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){" ascii
    $s15 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s16 = "ction fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return" ascii
    $s17 = "n fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"" ascii
    $s18 = " \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(functi" ascii
    $s19 = "(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";" ascii
    $s20 = "n \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}