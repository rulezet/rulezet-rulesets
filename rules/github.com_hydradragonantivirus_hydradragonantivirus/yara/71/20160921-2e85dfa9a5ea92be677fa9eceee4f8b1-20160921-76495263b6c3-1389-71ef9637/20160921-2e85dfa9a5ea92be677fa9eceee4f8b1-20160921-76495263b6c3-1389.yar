rule _20160921_2e85dfa9a5ea92be677fa9eceee4f8b1_20160921_76495263b6c3_1389 {
  meta:
    description = "datamaliciousorder - from files 20160921_2e85dfa9a5ea92be677fa9eceee4f8b1.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_ecd98b74e6a52b1227b09228f92cb495.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd958e388f97aa8b73e103ada622a36250446b5740c2e70d0bf844240c0968c2"
    hash2       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash3       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash4       = "8930637b40db8c97df91bff2cf5b4021d0bcb2f6a204f27249176fe3d6d4120e"

  strings:
    $s1  = "function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){ret" ascii
    $s2  = "urn \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s3  = "uck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ug" ascii
    $s4  = " fuck(){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"N" ascii
    $s5  = "u\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function " ascii
    $s6  = "(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck" ascii
    $s7  = "turn \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"ZWu\";})(),(" ascii
    $s8  = "n \"Dc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s9  = " fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s10 = "function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){r" ascii
    $s11 = "(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"EHo\";})(),(function fuck()" ascii
    $s12 = "eturn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})()," ascii
    $s13 = "\"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s14 = "{return \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}