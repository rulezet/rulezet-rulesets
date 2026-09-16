rule _20160921_cab66b13ccb843c90a2a068a082cd4ec_20160922_e3f5fbc84de1_5686 {
  meta:
    description = "datamaliciousorder - from files 20160921_cab66b13ccb843c90a2a068a082cd4ec.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"
    hash2       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "\"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(funct" ascii
    $s2 = "\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function" ascii
    $s3 = "turn \"Ot\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yi\";})(),(" ascii
    $s4 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\"" ascii
    $s5 = " f000(){return \"XTn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GG" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}