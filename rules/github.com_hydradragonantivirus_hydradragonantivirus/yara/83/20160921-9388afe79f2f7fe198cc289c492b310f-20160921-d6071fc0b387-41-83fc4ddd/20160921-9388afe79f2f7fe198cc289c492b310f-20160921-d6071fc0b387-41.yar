rule _20160921_9388afe79f2f7fe198cc289c492b310f_20160921_d6071fc0b387_41 {
  meta:
    description = "datamaliciousorder - from files 20160921_9388afe79f2f7fe198cc289c492b310f.js, 20160921_d6071fc0b387420da4f4d56c9cc4f29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd51f1b0a7122eb391698c985377ffff7f055696d2ab09fca71851b63308ba93"
    hash2       = "3582ec61c8d16a4dd7e6b8ba69c238b2abf1b60a1d05ebc8f672103586bdfd47"

  strings:
    $s1  = "(){return \"Qz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";}" ascii
    $s2  = "(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s3  = "})(),(function f000(){return \"OUx\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TKl\";})(),(function f0" ascii
    $s4  = "\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"Lp\";})(),(function " ascii
    $s5  = "turn \"RVb\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})()," ascii
    $s6  = "eturn \"SGs\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Sq\";})()," ascii
    $s7  = "ction f000(){return \"SEo\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qz\";})(),(function f000(){retur" ascii
    $s8  = "00(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj" ascii
    $s9  = ")(),(function f000(){return \"Yi\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TRc\";})(),(function f000" ascii
    $s10 = "000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Ml\"" ascii
    $s11 = "{return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Lp\";})()" ascii
    $s12 = "turn \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})()" ascii
    $s13 = "){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";}" ascii
    $s14 = "00(){return \"Qj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";" ascii
    $s15 = "on f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"" ascii
    $s16 = "){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"TKl\";" ascii
    $s17 = "0(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"GGn\"" ascii
    $s18 = "00(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Um\";}" ascii
    $s19 = "\"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(funct" ascii
    $s20 = "b\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}