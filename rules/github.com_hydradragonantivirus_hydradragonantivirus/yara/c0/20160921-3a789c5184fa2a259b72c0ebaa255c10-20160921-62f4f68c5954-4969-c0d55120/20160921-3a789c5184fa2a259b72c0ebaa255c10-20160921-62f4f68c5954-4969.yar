rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_62f4f68c5954_4969 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash3       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1 = "(){return \"CCb\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";" ascii
    $s2 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii
    $s3 = "IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(functio" ascii
    $s4 = "s\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(functio" ascii
    $s5 = "k(){return \"UXf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}