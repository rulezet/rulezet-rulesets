rule _20160921_6a795b29889480550a8440815b06fa7d_20160921_6f8e01604e95_332 {
  meta:
    description = "datamaliciousorder - from files 20160921_6a795b29889480550a8440815b06fa7d.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb5890246703edf23742bd2e821c50d1610d87dc3d17ff4909414fae3bd26d96"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1  = "n fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s2  = "ction fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s3  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4  = "Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(functio" ascii
    $s5  = "function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii
    $s6  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s7  = " \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s8  = "urn \"PDf\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s9  = "fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"UOe" ascii
    $s10 = ";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fu" ascii
    $s11 = "Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s12 = "uck(){return \"YAv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NK" ascii
    $s13 = "\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function " ascii
    $s14 = "})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck" ascii
    $s15 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s16 = "\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function " ascii
    $s17 = "ction fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s18 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(functio" ascii
    $s19 = "n \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ai\";})(),(fu" ascii
    $s20 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}