rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_5541f4e80ad2_4988 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_5541f4e80ad2d4f163ebcd0e8c899e59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "615edf37483855ab2b78dd87e38795245913e5fc6efc9bc47d9e698132792739"

  strings:
    $s1 = "(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Zj\";})(),(function f000(){r" ascii
    $s2 = "0(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s3 = "return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"BMj\";})()" ascii
    $s4 = "rn \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Wb\";})(),(fun" ascii
    $s5 = "){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}