rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_a41FOHj_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@a41FOHj_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6038b29cfb4ffb9e4c455021e2613a74422bcd1c08b837ff2ccd1dc13beff62e"

  strings:
    $s1 = "A(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii
    $s2 = "A(including the denial or cancellation of any export or other license); other event outside the reasonable control of the obliga" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}