rule _20160921_22785a85892e6eb0dbe789a8a528129f_20160921_3b3df29e27c3_1684 {
  meta:
    description = "datamaliciousorder - from files 20160921_22785a85892e6eb0dbe789a8a528129f.js, 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bd9f1cc39c45e7b6963f5eca04b26ef2eaf9c8005e5a0d5f12e868261ae58ca"
    hash2       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"

  strings:
    $s1  = "\"Um\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s2  = "000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s3  = "(),(function f000(){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";})(),(function f000()" ascii
    $s4  = "n f000(){return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return " ascii
    $s5  = "n \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZIi\";})(),(fu" ascii
    $s6  = "ction f000(){return \"Lp\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Nx\";})(),(function f000(){return " ascii
    $s7  = "(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"RPt\";})(),(function f000(){r" ascii
    $s8  = "turn \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn\";})()," ascii
    $s9  = "unction f000(){return \"Nv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"UEg\";})(),(function f000(){retu" ascii
    $s10 = "Rc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s11 = "n \"DYx\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"PTs\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}