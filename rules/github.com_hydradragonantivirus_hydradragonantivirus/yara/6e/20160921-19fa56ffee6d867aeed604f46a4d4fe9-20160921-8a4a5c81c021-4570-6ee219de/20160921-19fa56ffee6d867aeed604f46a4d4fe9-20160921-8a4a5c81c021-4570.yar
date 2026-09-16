rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_8a4a5c81c021_4570 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash3       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"
    hash4       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IOs\"" ascii
    $s2 = "uck(){return \"GJx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu" ascii
    $s3 = " \"MIl\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s4 = "rn \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(fu" ascii
    $s5 = " \"Wo0\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}