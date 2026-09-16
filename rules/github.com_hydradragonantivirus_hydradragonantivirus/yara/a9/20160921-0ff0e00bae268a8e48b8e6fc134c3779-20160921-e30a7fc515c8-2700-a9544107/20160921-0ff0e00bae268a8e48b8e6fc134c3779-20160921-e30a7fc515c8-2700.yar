rule _20160921_0ff0e00bae268a8e48b8e6fc134c3779_20160921_e30a7fc515c8_2700 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ff0e00bae268a8e48b8e6fc134c3779.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f9f30b45066ff23899a854b2ef766240b2becea05223ad11c6bf5cde97c3048"
    hash2       = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"

  strings:
    $s1 = "f000(){return \"Do\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"NBs" ascii
    $s2 = "return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})()" ascii
    $s3 = " \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(funct" ascii
    $s4 = "\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function " ascii
    $s5 = "unction f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){retu" ascii
    $s6 = ",(function f000(){return \"KXg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Kw\";})(),(function f000(){r" ascii
    $s7 = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}