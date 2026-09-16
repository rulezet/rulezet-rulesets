rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_d1c97b87a698_4200 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_d1c97b87a6985071e0e4edfb0e0dcc81.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "b5d1f1d63107b329353fe8130c80608d28a9b1ed12f81c240129d04be6842bf0"
    hash3       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash4       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(func" ascii
    $s2 = ",(function f000(){return \"Mu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){r" ascii
    $s3 = ",(function f000(){return \"Wy\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s4 = "00(){return \"QDg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TKl" ascii
    $s5 = "0(){return \"Qz\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}