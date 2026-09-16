rule _20160921_1267df6ebcd72f6d98872f0680fda2dd_20160921_73310531aa4a_4424 {
  meta:
    description = "datamaliciousorder - from files 20160921_1267df6ebcd72f6d98872f0680fda2dd.js, 20160921_73310531aa4a1df7337a6ef42003ce5e.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_97811319fb50bbd834b521ddcbb35712.js, 20160921_afee44f6d8e742fd9b103fa8b026b3b3.js, 20160921_b091a235428e4f2a03a39b034feca4b8.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf733ba7fbcc89931fdde522ae98997cc24f7014bdd535a49fc0223e8d0b0a2b"
    hash2       = "c1f6942ac4bb494bebef47181bbb9c9fe04d3d155e4bc18b2ff21e74c6592f78"
    hash3       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash4       = "4105b34a1f3797b1fc5f9b5d7f49d995c2796d5876f07b87b344f6c7e8c0625e"
    hash5       = "dd1fb060f8cf9db47b88f548c50d48e0e942b01aac86e408632eb9f913c96480"
    hash6       = "c42887396845595b9d299a51d83fefe371bc73c7bfbcd3105457a9327da7e441"
    hash7       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "{return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(" ascii
    $s2 = "uck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe" ascii
    $s3 = "turn \"IKv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s4 = "),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){" ascii
    $s5 = "){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}