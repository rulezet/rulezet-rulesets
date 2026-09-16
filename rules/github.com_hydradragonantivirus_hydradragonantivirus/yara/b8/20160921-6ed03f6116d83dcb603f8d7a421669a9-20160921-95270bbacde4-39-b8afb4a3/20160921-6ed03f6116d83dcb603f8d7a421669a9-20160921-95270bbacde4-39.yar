rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_95270bbacde4_39 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"

  strings:
    $s1  = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"MBb\";})(),(function f000()" ascii
    $s2  = "f000(){return \"Sv\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"MDb" ascii
    $s3  = "0(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KXg\"" ascii
    $s4  = "ion f000(){return \"Wh\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"BQb\";})(),(function f000(){return " ascii
    $s5  = "turn \"GGn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})()" ascii
    $s6  = "n f000(){return \"DNa\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"" ascii
    $s7  = "Vj\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s8  = "(){return \"ZFe\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\"" ascii
    $s9  = "function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DNa\";})(),(function f000(){re" ascii
    $s10 = "(function f000(){return \"PTs\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"UEg\";})(),(function f000(){r" ascii
    $s11 = "rn \"Ot\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(fun" ascii
    $s12 = "{return \"Sv\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})" ascii
    $s13 = "turn \"GGn\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})()" ascii
    $s14 = "return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"NYh\";})" ascii
    $s15 = "0(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"HJm\"" ascii
    $s16 = "\"EZu\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(funct" ascii
    $s17 = "ction f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh\";})(),(function f000(){retur" ascii
    $s18 = "return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})" ascii
    $s19 = "f000(){return \"Yi\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TR" ascii
    $s20 = " \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}