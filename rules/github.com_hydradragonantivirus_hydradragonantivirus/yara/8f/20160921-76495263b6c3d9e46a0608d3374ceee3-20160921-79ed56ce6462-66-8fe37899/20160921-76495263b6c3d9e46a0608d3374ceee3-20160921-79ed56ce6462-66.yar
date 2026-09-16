rule _20160921_76495263b6c3d9e46a0608d3374ceee3_20160921_79ed56ce6462_66 {
  meta:
    description = "datamaliciousorder - from files 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash2       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"

  strings:
    $s1  = " fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"C" ascii
    $s2  = "fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq" ascii
    $s3  = "ck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";" ascii
    $s4  = "k(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ve\";" ascii
    $s5  = "\"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Np\";})(),(funct" ascii
    $s6  = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return " ascii
    $s7  = "\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"QTc\";})(),(function f" ascii
    $s8  = "DAa\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s9  = "eturn \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s10 = "urn \"Ot\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Cd\";})(),(f" ascii
    $s11 = "urn \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(" ascii
    $s12 = "urn \"Xw\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s13 = "tion fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s14 = "(){return \"MUs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s15 = "k(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";" ascii
    $s16 = "n \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(fu" ascii
    $s17 = "\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function " ascii
    $s18 = "return \"Yk\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Qh\";})()," ascii
    $s19 = ",(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s20 = "Df\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}