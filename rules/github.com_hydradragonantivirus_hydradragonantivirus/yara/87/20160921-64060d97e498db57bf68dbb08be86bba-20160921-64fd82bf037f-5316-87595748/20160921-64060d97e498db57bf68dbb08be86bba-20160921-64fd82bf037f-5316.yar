rule _20160921_64060d97e498db57bf68dbb08be86bba_20160921_64fd82bf037f_5316 {
  meta:
    description = "datamaliciousorder - from files 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_95c689d7ff4700a03d604b71aaf3634b.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js, 20160921_cb95437e5f7b0cd43bdbd6381ee6a105.js, 20160921_f926399cbb634492c58e195c86a0bbde.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash2       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash3       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash4       = "5783f1dc6f93c438a9ac56abe49d6a41942b0b140e5fe608a7748f646ea646e7"
    hash5       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash6       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"
    hash7       = "46d771acb80357bcbb0857af9e7a4a35304fdbbf9785ec02f88f92f1268dfa71"
    hash8       = "15b29ae0204a4b512f15931b197f4e0ddaad99fc24c68356f1631bedc62dcac6"

  strings:
    $s1 = " \"UXf\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(func" ascii
    $s2 = "ction fuck(){return \"UXf\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retur" ascii
    $s3 = "k(){return \"Mw\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";}" ascii
    $s4 = "fuck(){return \"ZWu\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik" ascii
    $s5 = "(function fuck(){return \"UXf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}