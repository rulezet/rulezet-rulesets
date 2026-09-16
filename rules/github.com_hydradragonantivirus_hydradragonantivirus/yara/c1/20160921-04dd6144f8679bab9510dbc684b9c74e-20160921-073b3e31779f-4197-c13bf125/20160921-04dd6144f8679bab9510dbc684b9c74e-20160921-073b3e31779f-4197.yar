rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_073b3e31779f_4197 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_073b3e31779f349650fc6977a0add94b.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "60d01505d8ea4f2da2961c36fda33950e39ba720d54d967d434c0c5003ff7d2f"
    hash3       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash4       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "(function f000(){return \"GGn\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Yz\";})(),(function f000(){re" ascii
    $s2 = "ction f000(){return \"Mc\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s3 = "eturn \"OUx\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"MDb\";})()" ascii
    $s4 = "000(){return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"OMd" ascii
    $s5 = "BQb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"DIa\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}