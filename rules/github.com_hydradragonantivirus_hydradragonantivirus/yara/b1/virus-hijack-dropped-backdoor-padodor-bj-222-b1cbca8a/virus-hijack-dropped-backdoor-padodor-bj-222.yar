rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_222 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_222.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46d0dca18e347df40c1c7ca15b2c01da0fb19b13338f9c1cd3b34b316f36cc74"

  strings:
    $s1 = "must be a Qualified Educational User to use soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}