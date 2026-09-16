rule _20160921_64fd82bf037f1ee6b74269456349f2e6_20160921_75e390c1072b_3858 {
  meta:
    description = "datamaliciousorder - from files 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash2       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash3       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "ion fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s2 = "){return \"OQr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})" ascii
    $s3 = "(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s4 = "eturn \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Pc\";})(),(f" ascii
    $s5 = "ck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Py\";" ascii
    $s6 = " fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}