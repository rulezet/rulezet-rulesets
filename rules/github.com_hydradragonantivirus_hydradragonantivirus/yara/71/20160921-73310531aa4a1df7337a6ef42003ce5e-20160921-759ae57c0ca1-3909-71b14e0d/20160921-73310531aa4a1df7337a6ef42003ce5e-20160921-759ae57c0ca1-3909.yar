rule _20160921_73310531aa4a1df7337a6ef42003ce5e_20160921_759ae57c0ca1_3909 {
  meta:
    description = "datamaliciousorder - from files 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash2       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash3       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash4       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash5       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash6       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"
    hash7       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "rn \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(f" ascii
    $s2 = "turn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s3 = "n fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii
    $s4 = "fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb" ascii
    $s5 = "\"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s6 = "ion fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}