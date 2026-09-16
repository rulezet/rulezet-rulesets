rule _20160921_527d7c3756974f804734da343b6b6f0e_20160921_80e6ac924bf1_505 {
  meta:
    description = "datamaliciousorder - from files 20160921_527d7c3756974f804734da343b6b6f0e.js, 20160921_80e6ac924bf190eef40e43ba5d57f11b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2dd725d314277b3b7cf1c94ae8894dce1d36430ff22819c2fecb47f14c3f43"
    hash2       = "e240b858e2fac9be9a3fc0f8611c4c05e6f217dd1e13ac43649aa6d7597ee450"

  strings:
    $s1  = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000" ascii
    $s2  = " f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"" ascii
    $s3  = "{return \"Nx\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"XTn\";})(" ascii
    $s4  = "000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Wb\"" ascii
    $s5  = "\"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Yv\";})(),(func" ascii
    $s6  = "eturn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Uo\";})()," ascii
    $s7  = "){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Vu\";}" ascii
    $s8  = "tion f000(){return \"RPt\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s9  = "{return \"Qa\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn\";})(" ascii
    $s10 = ";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"NYh\";})(),(function f0" ascii
    $s11 = "00(){return \"XTn\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Lp" ascii
    $s12 = "\"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s13 = "turn \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";})(),(" ascii
    $s14 = "turn \"Kw\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"KXg\";})()," ascii
    $s15 = "),(function f000(){return \"RLk\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Qj\";})(),(function f000()" ascii
    $s16 = "(),(function f000(){return \"BMj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(" ascii
    $s17 = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MJq\";})(),(functi" ascii
    $s18 = "{return \"NYh\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s19 = "000(){return \"Wb\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb" ascii
    $s20 = "{return \"Lp\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}