rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_a8c002f684df_3456 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js, 20160921_f156e377f5219607c339e3053fbf1ae8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash3       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash4       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"
    hash5       = "05538f165c9450aa5ee129299544270acb99521d74bac943ca8cf157311609af"

  strings:
    $s1 = "function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){re" ascii
    $s2 = "n \"ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(fun" ascii
    $s3 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck()" ascii
    $s4 = "k(){return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s5 = "function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){re" ascii
    $s6 = "ck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}