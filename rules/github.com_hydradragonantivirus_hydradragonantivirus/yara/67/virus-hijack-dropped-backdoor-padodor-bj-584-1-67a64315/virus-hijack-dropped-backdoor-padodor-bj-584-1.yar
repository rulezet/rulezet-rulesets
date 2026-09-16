rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_584_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_584_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "34f59b4d0f20f13438558c06eeb4f614cb2b9b49c688bb49fc54987d7d31e25c"

  strings:
    $s1 = "slIm]lZ" fullword ascii
    $s2 = "D`LERP" fullword ascii
    $s3 = "BAck]~" fullword ascii
    $s4 = "SnUG#K" fullword ascii
    $s5 = "C\"lUMP" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}