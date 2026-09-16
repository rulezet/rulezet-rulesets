rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_814eb57aeffc_884 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash3       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"

  strings:
    $s1  = ",(function f000(){return \"Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})(),(function f000(){r" ascii
    $s2  = "Vj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(functio" ascii
    $s3  = "{return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})()" ascii
    $s4  = "(function f000(){return \"Oe\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"MMz\";})(),(function f000(){re" ascii
    $s5  = "000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KX" ascii
    $s6  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"" ascii
    $s7  = "unction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"KZr\";})(),(function f000(){retu" ascii
    $s8  = "){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"KXg\";" ascii
    $s9  = "),(function f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){" ascii
    $s10 = " \"Wb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"DIa\";})(),(func" ascii
    $s11 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f0" ascii
    $s12 = "00(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DIa\";" ascii
    $s13 = " \"QDg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s14 = "000(){return \"KXg\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"NBs" ascii
    $s15 = "(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){" ascii
    $s16 = "000(){return \"UEg\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"ZIi" ascii
    $s17 = "f000(){return \"GGn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do" ascii
    $s18 = "rn \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fu" ascii
    $s19 = "){return \"ZIi\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DIa\";})" ascii
    $s20 = "urn \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Sq\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}