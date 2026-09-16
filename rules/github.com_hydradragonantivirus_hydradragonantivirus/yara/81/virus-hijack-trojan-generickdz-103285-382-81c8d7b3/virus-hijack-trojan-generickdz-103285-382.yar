rule Virus_Hijack_Trojan_GenericKDZ_103285_382 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_382.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f605f190895dfeb3f365b212283d5b83d2a64046b5e1cb75180f82571769962f"

  strings:
    $s1 = "c2University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}