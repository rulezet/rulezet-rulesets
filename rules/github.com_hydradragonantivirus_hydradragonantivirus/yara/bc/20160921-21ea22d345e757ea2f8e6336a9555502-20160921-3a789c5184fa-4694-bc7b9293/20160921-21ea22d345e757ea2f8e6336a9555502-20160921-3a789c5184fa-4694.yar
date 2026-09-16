rule _20160921_21ea22d345e757ea2f8e6336a9555502_20160921_3a789c5184fa_4694 {
  meta:
    description = "datamaliciousorder - from files 20160921_21ea22d345e757ea2f8e6336a9555502.js, 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8743d09e1e870afab5e1ecd8d21f82873a9da6a025b74f14bc65477cea8f023"
    hash2       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash3       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash4       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1 = "b\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s2 = "s\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(functio" ascii
    $s3 = "k(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\"" ascii
    $s4 = "IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(funct" ascii
    $s5 = "fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}