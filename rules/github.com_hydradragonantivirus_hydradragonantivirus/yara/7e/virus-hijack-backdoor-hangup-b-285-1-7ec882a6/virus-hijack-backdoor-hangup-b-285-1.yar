rule Virus_Hijack_Backdoor_Hangup_B_285_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_285_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d23d10c7b0c144426f8ae02d6d1f738ea5546dcf1e2fe9edfb88e9f236fe3371"

  strings:
    $s1 = "Virtual@L" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}