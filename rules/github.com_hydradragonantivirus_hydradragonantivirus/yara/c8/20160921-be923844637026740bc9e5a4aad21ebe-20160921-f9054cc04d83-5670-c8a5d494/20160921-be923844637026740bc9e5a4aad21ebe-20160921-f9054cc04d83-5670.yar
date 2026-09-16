rule _20160921_be923844637026740bc9e5a4aad21ebe_20160921_f9054cc04d83_5670 {
  meta:
    description = "datamaliciousorder - from files 20160921_be923844637026740bc9e5a4aad21ebe.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js, 20160922_b9c8ae1e2648708b7b599ba2ac6333c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f50e7368497d3ab714aae3798280c1b53ff9f91f0081f1eafa0b9e23e4928336"
    hash2       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash3       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"
    hash4       = "e2b244eea80e558d4ae468572be8ba3fade8163b0f8751b10ba6ca2263421085"

  strings:
    $s1 = "Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s2 = "return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})()" ascii
    $s3 = "on f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii
    $s4 = "on f000(){return \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s5 = "\"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}