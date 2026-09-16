rule _20160921_8a4a5c81c02126f78061e6b947b8f9bc_20160921_c6bbdc353079_3961 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js, 20160921_e78383c7f2f16b29dbde839d36607f19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash2       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"
    hash3       = "3b18cb17d7caf150b505c169cb67d810f1ccee674cf86164682bf91d285bd02a"

  strings:
    $s1 = "e\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(functio" ascii
    $s2 = "IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(funct" ascii
    $s3 = ",(function fuck(){return \"XCr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){r" ascii
    $s4 = "(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"USf\";}" ascii
    $s5 = "rn \"XHj\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s6 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}