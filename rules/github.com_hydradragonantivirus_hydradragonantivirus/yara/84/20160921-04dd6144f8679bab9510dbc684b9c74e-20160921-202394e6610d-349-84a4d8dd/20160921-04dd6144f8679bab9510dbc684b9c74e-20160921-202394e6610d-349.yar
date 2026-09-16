rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_202394e6610d_349 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash3       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash4       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1  = "0(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"GGn" ascii
    $s2  = "return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s3  = "function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})(),(function f000(){retu" ascii
    $s4  = "rn \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Zj\";})(),(fun" ascii
    $s5  = "){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(" ascii
    $s6  = "\"OUx\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Yz\";})(),(functi" ascii
    $s7  = "000(){return \"Lp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc" ascii
    $s8  = " f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Zj" ascii
    $s9  = ";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"MMz\";})(),(function f0" ascii
    $s10 = "f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj" ascii
    $s11 = "Fe\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s12 = "tion f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return " ascii
    $s13 = "tion f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){retur" ascii
    $s14 = "return \"ZIi\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(" ascii
    $s15 = "(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";}" ascii
    $s16 = "),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"TKl\";})(),(function f000(){" ascii
    $s17 = "(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";}" ascii
    $s18 = "\"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(funct" ascii
    $s19 = "(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){re" ascii
    $s20 = "turn \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TRc\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}