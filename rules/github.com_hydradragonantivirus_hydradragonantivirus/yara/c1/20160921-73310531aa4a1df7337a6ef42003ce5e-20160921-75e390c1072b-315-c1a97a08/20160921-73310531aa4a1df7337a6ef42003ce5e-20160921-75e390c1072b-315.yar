rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_75e390c1072b_315 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash3       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash4       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1  = "uck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn" ascii
    $s2  = "fuck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UO" ascii
    $s3  = "turn \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})()," ascii
    $s4  = "n fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s5  = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii
    $s6  = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuc" ascii
    $s7  = ",(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck()" ascii
    $s8  = "eturn \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})()," ascii
    $s9  = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s10 = "fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DR" ascii
    $s11 = " fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"P" ascii
    $s12 = "\"IPu\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s13 = "USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(functi" ascii
    $s14 = "ction fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retur" ascii
    $s15 = "ck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\"" ascii
    $s16 = "){return \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})" ascii
    $s17 = "Cr\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functi" ascii
    $s18 = "),(function fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(" ascii
    $s19 = "){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(" ascii
    $s20 = "){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}