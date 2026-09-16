rule _20160921_1d5a5ba6420732e8f626755a81334ad4_20160921_5143fd2835d0_1385 {
  meta:
    description = "datamaliciousorder - from files 20160921_1d5a5ba6420732e8f626755a81334ad4.js, 20160921_5143fd2835d058f3854ef7b166166de4.js, 20160921_76495263b6c3d9e46a0608d3374ceee3.js, 20160921_79ed56ce6462f4777520d97fc535fdf5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47a1fbd3f8785b259468283f9d6611b34da6b0170d66a933ade09c56548f89b4"
    hash2       = "0824c6197846b6efc3bea2626d4bc5983302ec11dd40189770e6572811d3d42c"
    hash3       = "7cff9275d0250bfdb50a193691ce5f5102aebf80af9793212683e5ddde59dc73"
    hash4       = "eeffea004f5e955937d1ae0a312f76837c366f381494eff12911d267efcb2e6a"

  strings:
    $s1  = "\"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(func" ascii
    $s2  = "k(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";}" ascii
    $s3  = "eturn \"Zy\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})()," ascii
    $s4  = "(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})" ascii
    $s5  = ";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s6  = "nction fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s7  = " fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s8  = "ck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\"" ascii
    $s9  = "x\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function" ascii
    $s10 = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return" ascii
    $s11 = "nction fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retu" ascii
    $s12 = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){retur" ascii
    $s13 = "fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IP" ascii
    $s14 = "IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}