rule _20160921_76495263b6c3d9e46a0608d3374ceee3_20160921_79ed56ce6462_3915 {
  meta:
    description = "datamaliciousorder - from files 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js, 20160921_ef5539a74fa92cc432f92987e238b0be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash2       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"
    hash3       = "6a7080b4743207e49b99932d406b2ee18d652ac2222bdb5a88a66af8dea13c80"

  strings:
    $s1 = "ion fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2 = "turn \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})()," ascii
    $s3 = "tion fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s4 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){ret" ascii
    $s5 = "rn \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s6 = " fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}