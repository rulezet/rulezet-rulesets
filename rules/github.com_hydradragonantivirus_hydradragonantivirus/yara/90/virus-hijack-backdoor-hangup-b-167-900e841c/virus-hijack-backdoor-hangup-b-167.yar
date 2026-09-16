rule Virus_Hijack_Backdoor_Hangup_B_167 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_167.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfe208fda35e41dac6361a0dd0ec5a1127aa5ac367f15a9e04cb5a500cee424e"

  strings:
    $s1 = "aTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}