rule _20160921_3d472332b6f7d53a9f60478e1312ea58_20160921_5775da34d70f_5007 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_8ac006dedc6205f05757feeef6cd894a.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash2       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash3       = "00e17d6bd534b2582622ec06dbd3fa43882b34044fc369b6707b8d580a7cc293"
    hash4       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"

  strings:
    $s1 = " f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"" ascii
    $s2 = "turn \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(" ascii
    $s3 = "Ij\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(functi" ascii
    $s4 = "OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Yi\";})(),(functio" ascii
    $s5 = "n\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"KXg\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}