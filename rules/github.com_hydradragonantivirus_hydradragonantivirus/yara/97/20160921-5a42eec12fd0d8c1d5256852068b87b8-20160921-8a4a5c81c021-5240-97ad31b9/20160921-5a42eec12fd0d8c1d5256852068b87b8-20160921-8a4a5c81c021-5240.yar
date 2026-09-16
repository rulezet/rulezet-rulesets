rule _20160921_5a42eec12fd0d8c1d5256852068b87b8_20160921_8a4a5c81c021_5240 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42eec12fd0d8c1d5256852068b87b8.js, 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"
    hash2       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash3       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"

  strings:
    $s1 = "fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"G" ascii
    $s2 = "ck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "o\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s4 = "tion fuck(){return \"DWe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s5 = "return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}