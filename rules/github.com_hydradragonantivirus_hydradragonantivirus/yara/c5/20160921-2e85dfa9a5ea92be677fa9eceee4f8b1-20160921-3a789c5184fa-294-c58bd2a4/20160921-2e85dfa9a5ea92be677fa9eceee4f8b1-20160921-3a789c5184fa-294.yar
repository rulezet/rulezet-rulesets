rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_3a789c5184fa_294 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash3       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"
    hash4       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1  = "turn \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(" ascii
    $s2  = "rn \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s3  = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s4  = "n \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s5  = " \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Dc\";})(),(fun" ascii
    $s6  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s7  = "b\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s8  = "rn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s9  = "rn \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(fu" ascii
    $s10 = "FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(functi" ascii
    $s11 = "ck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\"" ascii
    $s12 = "k(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"USf" ascii
    $s13 = "(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";}" ascii
    $s14 = "eturn \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s15 = "\"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(functi" ascii
    $s16 = " fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"C" ascii
    $s17 = " \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s18 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"GJx\";})(" ascii
    $s19 = "f\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Wo0\";})(),(functio" ascii
    $s20 = "ck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Np\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}