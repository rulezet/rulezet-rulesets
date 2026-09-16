rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_3a888f864f15_4972 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_acea633b73985995ce9764bf94db0972.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash3       = "dd77df78b3a755b016a27bbcac8fe7c015ab04472e2ca2d2d9aa476befb3148a"
    hash4       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1 = "Ts\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s2 = ";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fu" ascii
    $s3 = "on fuck(){return \"DHd\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s4 = "n fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s5 = "eturn \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}