rule _20160921_47da6150745eccf8bd846591c67ec5e7_20160921_6a2eea5014c6_5081 {
  meta:
    description = "datamaliciousorder - from files 20160921_47da6150745eccf8bd846591c67ec5e7.js, 20160921_6a2eea5014c6e10514154c4a8ee7c1be.js, 20160921_cab66b13ccb843c90a2a068a082cd4ec.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6547815adb02f36991578330e4cb005f8225b3a8e4c85d5e2c5907a22e325c"
    hash2       = "b1fa490690ec2cf24ba4236d1fa675827bce812ac4cd92a59a9b5261b979f8a3"
    hash3       = "ce3b033b39aaca0b7c9abd0fc5eeb09d24d7096d0a399cebd99f7bd8d574f0d1"

  strings:
    $s1 = "eturn \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Lo\";})()" ascii
    $s2 = "u\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s3 = "n \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s4 = "00(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"KXg\";" ascii
    $s5 = "on f000(){return \"RPt\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"RPt\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}