rule _20160921_232b12ddd1b901389868a9b4ede90a00_20160921_75e390c1072b_4725 {
  meta:
    description = "datamaliciousorder - from files 20160921_232b12ddd1b901389868a9b4ede90a00.js, 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_a10895ba237c1e6f37301bc7a7a20160.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6982702aaaeaeac05c8666dd848834fd26e9eba567a0d41d04253252c120cdfe"
    hash2       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash3       = "a07dda373b4221628323bb92f53033ef3290be02ec657056fbf01d7d1efe96d7"
    hash4       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1 = "})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OPz\";})(),(function fuc" ascii
    $s2 = "function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){r" ascii
    $s3 = "{return \"UXf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Wo\";})(" ascii
    $s4 = "(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){" ascii
    $s5 = "ck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}