rule Virus_Hijack_Backdoor_Hangup_B_309_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_309_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c5d7ed3e1d64c5a3bc2ca76d0c8d1467625de95d58d1e95ceda90825a014dda"

  strings:
    $s1 = "Color@&B" fullword ascii
    $s2 = "Height,%B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}