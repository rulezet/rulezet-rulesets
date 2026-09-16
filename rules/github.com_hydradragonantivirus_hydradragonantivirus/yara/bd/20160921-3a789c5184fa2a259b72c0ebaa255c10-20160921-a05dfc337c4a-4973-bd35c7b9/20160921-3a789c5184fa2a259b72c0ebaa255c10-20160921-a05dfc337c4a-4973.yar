rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_a05dfc337c4a_4973 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_a05dfc337c4ada28e05759b304eef904.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "db6a3cf7e8281867bf38b22cce5a945336377679a1a85ee91d365e41ec94182c"
    hash3       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1 = " fuck(){return \"Xw\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw" ascii
    $s2 = "rn \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(f" ascii
    $s3 = "turn \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s4 = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(),(function fuc" ascii
    $s5 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}