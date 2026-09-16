rule _20160921_3a789c5184fa2a259b72c0ebaa255c10_20160921_3bd7e22bf014_3662 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a789c5184fa2a259b72c0ebaa255c10.js, 20160921_3bd7e22bf0147340b20eeb7a825cb9a1.js, 20160921_bd3b4c7cf0588af7c4014d66947dd198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db17c9f665e5fe0e02b03fbde1c9c388c4600d6d7ec9c3890464b11ceab9fc9d"
    hash2       = "fabcf64721727f8848bd26426a6a8b0fdf115e6416d2ce71dfa09efadb821690"
    hash3       = "b6d0dad910056c72d41faa066846061b7a1630e389a231f1b551dd9947342637"

  strings:
    $s1 = "k(){return \"Vf\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";" ascii
    $s2 = "function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){re" ascii
    $s3 = "){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"GNm\";}" ascii
    $s4 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){ret" ascii
    $s5 = "Us\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii
    $s6 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}