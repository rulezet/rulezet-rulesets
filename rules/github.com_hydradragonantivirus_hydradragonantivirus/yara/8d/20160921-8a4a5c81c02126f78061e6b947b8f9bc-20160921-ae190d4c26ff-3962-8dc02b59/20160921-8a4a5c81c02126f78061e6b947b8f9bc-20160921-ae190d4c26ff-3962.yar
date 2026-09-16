rule _20160921_8a4a5c81c02126f78061e6b947b8f9bc_20160921_ae190d4c26ff_3962 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash3       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"

  strings:
    $s1 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"IOs\";})(),(function fuck" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"GWo\";})(),(func" ascii
    $s3 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQ" ascii
    $s4 = "urn \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s5 = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retur" ascii
    $s6 = "\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Np\";})(),(function f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}