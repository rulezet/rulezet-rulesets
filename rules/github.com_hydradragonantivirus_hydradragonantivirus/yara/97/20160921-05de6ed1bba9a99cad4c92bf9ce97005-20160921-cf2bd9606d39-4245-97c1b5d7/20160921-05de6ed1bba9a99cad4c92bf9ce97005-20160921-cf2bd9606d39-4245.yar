rule _20160921_05de6ed1bba9a99cad4c92bf9ce97005_20160921_cf2bd9606d39_4245 {
  meta:
    description = "datamaliciousorder - from files 20160921_05de6ed1bba9a99cad4c92bf9ce97005.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc9a1bb338cbe502eae2d8092d1b4369f9be8a107f4db340bf51a1640991e960"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1 = ",(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vj\";})(),(function f000(){" ascii
    $s2 = ",(function f000(){return \"Kw\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){r" ascii
    $s3 = "})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(function f000(" ascii
    $s4 = "u\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function f" ascii
    $s5 = "turn \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}