rule _20160921_882f77897bba85afdc56810c29ef4cbb_20160921_cab66b13ccb8_2528 {
  meta:
    description = "datamaliciousorder - from files 20160921_882f77897bba85afdc56810c29ef4cbb.js, 20160921_cab66b13ccb843c90a2a068a082cd4ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e1a86c6dc71a5b10659658c07a01bb1541887750ecf88ab56997c7dbc2d180c"
    hash2       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"

  strings:
    $s1 = "Ux\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"XTn\";})(),(functio" ascii
    $s2 = " f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"V" ascii
    $s3 = "\"Um\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})(),(functi" ascii
    $s4 = "j\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s5 = "){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"Iq\";}" ascii
    $s6 = "ction f000(){return \"Vj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TRc\";})(),(function f000(){return" ascii
    $s7 = "function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s8 = "urn \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}