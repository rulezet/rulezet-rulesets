rule Virus_Hijack_GenPack_Backdoor_Hangup_B_462 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_462.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f497db8d4b9ffa3dc9e01d00a82f8bb3fede44e3ab4048cf5bc483259a5831d7"

  strings:
    $s1 = "$/your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}