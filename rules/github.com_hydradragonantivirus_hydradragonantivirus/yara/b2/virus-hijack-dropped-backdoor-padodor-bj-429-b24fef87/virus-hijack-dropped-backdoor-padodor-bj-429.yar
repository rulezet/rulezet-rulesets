rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_429 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_429.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1198d89a77a0f8bd757f56e456b8b76a64ee3cced3fb7a8f02ad625a2d9799d3"

  strings:
    $s1 = "_UIf you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}