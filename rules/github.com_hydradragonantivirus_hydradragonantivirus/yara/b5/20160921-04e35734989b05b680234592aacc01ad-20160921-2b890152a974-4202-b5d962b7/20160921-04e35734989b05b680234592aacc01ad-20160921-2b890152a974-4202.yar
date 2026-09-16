rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_4202 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash4       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash5       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "uck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s2 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){r" ascii
    $s3 = "n fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"" ascii
    $s4 = "),(function fuck(){return \"Vf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck()" ascii
    $s5 = "\"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}