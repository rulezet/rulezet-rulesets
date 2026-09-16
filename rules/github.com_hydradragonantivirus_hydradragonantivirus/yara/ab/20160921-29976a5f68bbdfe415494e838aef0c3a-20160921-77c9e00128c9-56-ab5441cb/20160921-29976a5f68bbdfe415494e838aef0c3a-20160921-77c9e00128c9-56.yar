rule _20160921_29976a5f68bbdfe415494e838aef0c3a_20160921_77c9e00128c9_56 {
  meta:
    description = "datamaliciousorder - from files 20160921_29976a5f68bbdfe415494e838aef0c3a.js, 20160921_77c9e00128c9a883c23909fbb2c12569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218bc62c15296caf93128e0a5e06fde374e19fd4150b6c9b1def4d962554ef39"
    hash2       = "95544bd07dbc8b2550e3a6bb328d49a808c8749bb3ced90cbb8f5f90782625a1"

  strings:
    $s1  = "\"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SGs\";})(),(functi" ascii
    $s2  = "\"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(functi" ascii
    $s3  = "turn \"OUx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Vu\";})(),(f" ascii
    $s4  = "n f000(){return \"ZFe\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s5  = "){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";}" ascii
    $s6  = "rn \"OUx\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZFe\";})(),(f" ascii
    $s7  = "rn \"Vu\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Ot\";})(),(fun" ascii
    $s8  = " f000(){return \"BMj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"D" ascii
    $s9  = "eturn \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(" ascii
    $s10 = "ction f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s11 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(" ascii
    $s12 = " \"QDg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(funct" ascii
    $s13 = "(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000()" ascii
    $s14 = "n \"Uo\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fun" ascii
    $s15 = "return \"GGn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"TRc\";})()" ascii
    $s16 = "ction f000(){return \"Kw\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s17 = "\"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(functi" ascii
    $s18 = "rn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(fu" ascii
    $s19 = "Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s20 = "i\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}