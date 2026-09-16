rule _20160921_3b3df29e27c35ab2e50a3446fa67bf66_20160921_80e6ac924bf1_1844 {
  meta:
    description = "datamaliciousorder - from files 20160921_3b3df29e27c35ab2e50a3446fa67bf66.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd15d322a8169ff9edb922ead245c93109f14c5fa4f31811eb58601888323ad2"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"

  strings:
    $s1  = "0(){return \"DYs\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"DIa\"" ascii
    $s2  = "eturn \"KDh\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";})()" ascii
    $s3  = "eturn \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Sq\";})()," ascii
    $s4  = "(),(function f000(){return \"Qj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s5  = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Qa\";})(),(fu" ascii
    $s6  = " f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"" ascii
    $s7  = ",(function f000(){return \"MKa\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Do\";})(),(function f000(){" ascii
    $s8  = "unction f000(){return \"Sj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Vu\";})(),(function f000(){retur" ascii
    $s9  = "unction f000(){return \"Yz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s10 = "n f000(){return \"PTi\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}