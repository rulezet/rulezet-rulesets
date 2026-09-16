rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_489 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_489.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e934082080c0830a1ef7ca1789b186a24644b1f07006243919dfcf2e173c424"

  strings:
    $s1 = "/}are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}