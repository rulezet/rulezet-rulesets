rule _20160921_1f7d568f432abb102bc2d5dbd6c68c22_20160921_f9054cc04d83_3487 {
  meta:
    description = "datamaliciousorder - from files 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = "0(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";" ascii
    $s2 = "Kl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3 = "g\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function " ascii
    $s4 = "),(function f000(){return \"Mu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){r" ascii
    $s5 = "0(){return \"GGn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";" ascii
    $s6 = "\"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}