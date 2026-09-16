rule _20160921_5c25506bc44b50a0c8028dec6521139d_20160921_9e9f1aaa0e05_5244 {
  meta:
    description = "datamaliciousorder - from files 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash2       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"
    hash3       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1 = "ction fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return" ascii
    $s2 = "\"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s3 = "eturn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(" ascii
    $s4 = " \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s5 = "k(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}