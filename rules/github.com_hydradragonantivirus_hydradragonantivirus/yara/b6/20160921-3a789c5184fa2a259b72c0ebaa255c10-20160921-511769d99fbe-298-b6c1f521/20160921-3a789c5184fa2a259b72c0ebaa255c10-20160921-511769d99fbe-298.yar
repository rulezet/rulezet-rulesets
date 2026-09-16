rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_511769d99fbe_298 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_511769d99fbe4d59a2e55781fb0eb77c.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"
    hash3       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1  = "(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){re" ascii
    $s2  = "o\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3  = "g\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function" ascii
    $s4  = "\"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s5  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s6  = "nction fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s7  = "n \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(func" ascii
    $s8  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s9  = "return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})" ascii
    $s10 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s11 = "urn \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})()," ascii
    $s12 = "on fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s13 = "ction fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s14 = "return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Yk\";})(" ascii
    $s15 = "n fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s16 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s17 = "Pu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Np\";})(),(function" ascii
    $s18 = "ck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np" ascii
    $s19 = "Kv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii
    $s20 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}