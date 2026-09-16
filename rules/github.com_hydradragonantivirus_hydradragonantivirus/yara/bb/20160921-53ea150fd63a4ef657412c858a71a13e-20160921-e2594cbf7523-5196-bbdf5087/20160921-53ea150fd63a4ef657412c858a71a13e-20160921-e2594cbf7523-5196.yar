rule _20160921_53ea150fd63a4ef657412c858a71a13e_20160921_e2594cbf7523_5196 {
  meta:
    description = "datamaliciousorder - from files 20160921_53ea150fd63a4ef657412c858a71a13e.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_f9054cc04d83c2e4156f98873a8df799.js, 20160921_fbc9133aa5350aa4ce872cb5927c8f4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16ac7affa46e10764a6e40de21c545ac275939c77c4acf142df8e3f848362242"
    hash2       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash3       = "7cfaa97d52690e3fa38d039126186e468701b138b24622f48887707d5da022f0"
    hash4       = "520ea6f275b172709ff81bfec4d8a5a9f734ab080b25e7c50bfe2a36800af6e3"

  strings:
    $s1 = " \"Mu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(fun" ascii
    $s2 = "n \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(fu" ascii
    $s3 = ",(function f000(){return \"QDg\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000()" ascii
    $s4 = "return \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})()" ascii
    $s5 = "OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}