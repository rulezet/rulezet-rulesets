rule Virus_Hijack_Backdoor_Hangup_B_54_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_54_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b53a3cdb7a0e1b09e74870554fb6aa1018941771f2d4ed541ac4945c11c2ac"

  strings:
    $s1 = "WhIr tf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}