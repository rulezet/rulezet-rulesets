rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_37b52e41aabc_3559 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash3       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"

  strings:
    $s1 = "\"Vu\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(functi" ascii
    $s2 = "(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"XTn\";})(),(function f000(" ascii
    $s3 = "nction f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii
    $s4 = "f000(){return \"EZu\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"UE" ascii
    $s5 = "f000(){return \"Qz\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn" ascii
    $s6 = "n f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"G" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}