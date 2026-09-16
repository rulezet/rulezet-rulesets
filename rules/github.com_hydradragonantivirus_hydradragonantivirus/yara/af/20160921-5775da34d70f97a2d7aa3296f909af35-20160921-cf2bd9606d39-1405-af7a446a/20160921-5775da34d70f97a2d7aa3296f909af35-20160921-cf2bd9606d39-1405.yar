rule _20160921_5775da34d70f97a2d7aa3296f909af35_20160921_cf2bd9606d39_1405 {
  meta:
    description = "datamaliciousorder - from files 20160921_5775da34d70f97a2d7aa3296f909af35.js, 20160921_cf2bd9606d396ba99f8174f1946c8590.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "270e1d840937d10ac3eb1fdd04f0fbbbfd31a88a2f316c94c5167a23a2940644"
    hash2       = "c5afd84ebe18fa55c764dd8e7349bc7b9cd8b10ab8d94500cbf7f62bd741c00d"

  strings:
    $s1  = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"MMz\";})(),(functi" ascii
    $s2  = "Sj\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s3  = "{return \"Br\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})()" ascii
    $s4  = "eturn \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Oe\";})(),(" ascii
    $s5  = "(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Fs\";})(),(function f000(){re" ascii
    $s6  = "(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s7  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){retu" ascii
    $s8  = "rn \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(fu" ascii
    $s9  = "urn \"Lo\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(" ascii
    $s10 = "ction f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s11 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(functio" ascii
    $s12 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"HJm\";})(),(function f000" ascii
    $s13 = "){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Qa\";})" ascii
    $s14 = "ction f000(){return \"Qa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Nx\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}