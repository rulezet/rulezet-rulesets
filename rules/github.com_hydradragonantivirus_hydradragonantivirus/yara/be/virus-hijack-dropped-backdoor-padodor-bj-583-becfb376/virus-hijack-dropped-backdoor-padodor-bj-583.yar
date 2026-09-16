rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_583 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_583.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c78a76b90f8612adfa9d0d205cccb4ac071d47a4e8563a8a467ddc95bcaf4b32"

  strings:
    $s1 = "iprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}