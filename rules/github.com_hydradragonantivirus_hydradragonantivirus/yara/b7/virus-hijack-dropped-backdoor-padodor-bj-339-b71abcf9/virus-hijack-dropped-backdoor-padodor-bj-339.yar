rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_339 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_339.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b82c4617c6131116089cc00d44232c93acb10f2c2d4de34e6d98d8381a24af0a"

  strings:
    $s1 = "9and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}