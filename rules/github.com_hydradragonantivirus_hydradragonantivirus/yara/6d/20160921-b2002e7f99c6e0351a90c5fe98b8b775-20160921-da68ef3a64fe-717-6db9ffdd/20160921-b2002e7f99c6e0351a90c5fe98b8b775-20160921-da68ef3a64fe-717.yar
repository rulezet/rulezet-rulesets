rule _20160921_b2002e7f99c6e0351a90c5fe98b8b775_20160921_da68ef3a64fe_717 {
  meta:
    description = "datamaliciousorder - from files 20160921_b2002e7f99c6e0351a90c5fe98b8b775.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e6376c7075a97cbb4e180ac5ea89ade4f5170dd182e1014b19fd2ed4aa33345"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1  = " f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"" ascii
    $s2  = "0(){return \"Qa\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\"" ascii
    $s3  = "f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s4  = "\"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(funct" ascii
    $s5  = "000(){return \"Sq\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"EZu" ascii
    $s6  = "(function f000(){return \"TKp\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";})(),(function f000(){re" ascii
    $s7  = ",(function f000(){return \"Qa\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s8  = "00(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BIj" ascii
    $s9  = "return \"Mu\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})()" ascii
    $s10 = "eturn \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})()" ascii
    $s11 = "f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj" ascii
    $s12 = "tion f000(){return \"UOt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s13 = "rn \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s14 = "\"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(functi" ascii
    $s15 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000" ascii
    $s16 = "urn \"Qj\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(f" ascii
    $s17 = "turn \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(" ascii
    $s18 = "f000(){return \"Tn\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IA" ascii
    $s19 = "{return \"OUx\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"KZr\";})" ascii
    $s20 = "n f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}