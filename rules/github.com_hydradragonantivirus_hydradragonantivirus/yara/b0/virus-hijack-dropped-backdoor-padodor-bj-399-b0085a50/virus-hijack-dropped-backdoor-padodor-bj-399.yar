rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_399 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_399.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04c4ebbf89e9ea2cb866a74fb63eb74008878a675578eeca4ed4b19be1ced5c7"

  strings:
    $s1 = "Iprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}