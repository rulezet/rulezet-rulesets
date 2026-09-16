rule _20160921_04dd6144f8679bab9510dbc684b9c74e_20160921_334dc22c3620_2629 {
  meta:
    description = "datamaliciousorder - from files 20160921_04dd6144f8679bab9510dbc684b9c74e.js, 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160922_4dfe760897656c6a111dd28b33055e75.js, 20160922_ed715c18f1a8b288b3a2daf159dfdcd6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97824f5d282c20ba44b29b6dd0ffef72c3a4a7419c474527e64dfb49c4f0cb89"
    hash2       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash3       = "76bf32cf7f7f6a161a3026c310b904328d9bce752e8955fb620779c62c11a6f5"
    hash4       = "d20943739c1e8a30074140436d0501b5156b43d83a6fd59a63cb1a5a8cb78432"

  strings:
    $s1 = "eturn \"Yi\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"MBb\";})()," ascii
    $s2 = "unction f000(){return \"Lp\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s3 = "i\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Uo\";})(),(function" ascii
    $s4 = ",(function f000(){return \"MDb\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s5 = "{return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Sj\";})(" ascii
    $s6 = "0(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"SGs\"" ascii
    $s7 = "ion f000(){return \"SEo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}