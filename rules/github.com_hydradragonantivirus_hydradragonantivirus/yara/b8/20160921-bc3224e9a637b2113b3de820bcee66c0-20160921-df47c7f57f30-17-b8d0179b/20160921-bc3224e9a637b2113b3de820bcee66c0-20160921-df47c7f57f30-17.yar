rule _20160921_bc3224e9a637b2113b3de820bcee66c0_20160921_df47c7f57f30_17 {
  meta:
    description = "datamaliciousorder - from files 20160921_bc3224e9a637b2113b3de820bcee66c0.js, 20160921_df47c7f57f308287ca344dcc34150b37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65d11827de99ef59cd2cc61d914e235dd2b16ac6b8f4f65f39b8a79dad86ed57"
    hash2       = "dbb4502419f8afb7a2d5fc4186a2c7922701956498b55deb8c27312672415d9c"

  strings:
    $s1  = "){return \"EHo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s2  = "urn \"Xw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s3  = "uck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IR" ascii
    $s4  = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck()" ascii
    $s5  = " fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"L" ascii
    $s6  = ",(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s7  = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s8  = "(function fuck(){return \"PDf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s9  = "function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){re" ascii
    $s10 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"YA" ascii
    $s11 = "ck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn" ascii
    $s12 = "(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";" ascii
    $s13 = "Bg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"USf\";})(),(functi" ascii
    $s14 = "tion fuck(){return \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s15 = "\"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(func" ascii
    $s16 = "Tc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s17 = "urn \"GNm\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s18 = "\"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s19 = "Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s20 = "eturn \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}