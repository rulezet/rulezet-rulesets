rule _20160921_8a4a5c81c02126f78061e6b947b8f9bc_20160921_c6bbdc353079_4 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a4a5c81c02126f78061e6b947b8f9bc.js, 20160921_c6bbdc353079233dc4959e9d0d85bc2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3543e3d5dddde5efe5675e5ec649f9614fc6d9e81a903f893466af300e1dc64b"
    hash2       = "6fbb4e2c3fc90d9c1f39093c60f9a0294627c14ec844d16cb99b4f2b5fc1c158"

  strings:
    $s1  = "fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"C" ascii
    $s2  = "eturn \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})()" ascii
    $s3  = "),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck()" ascii
    $s4  = "rn \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(f" ascii
    $s5  = "fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm" ascii
    $s6  = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"YQt\";})" ascii
    $s7  = "rn \"YQt\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s8  = "(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){" ascii
    $s9  = "nction fuck(){return \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s10 = "on fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s11 = "urn \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s12 = "){return \"Jh\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";}" ascii
    $s13 = ";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"MUs\";})(),(function fu" ascii
    $s14 = "on fuck(){return \"PDf\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return " ascii
    $s15 = "k(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s16 = "ck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq" ascii
    $s17 = "(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck" ascii
    $s18 = "rn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YQt\";})(),(fu" ascii
    $s19 = " \"Yk\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(func" ascii
    $s20 = "turn \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Fv\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}