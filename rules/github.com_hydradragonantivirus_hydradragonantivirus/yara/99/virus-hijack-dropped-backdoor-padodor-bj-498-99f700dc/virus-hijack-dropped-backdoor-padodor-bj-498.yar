rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_498 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_498.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcfc3e9476d94f26c85169c58f80258dd30e5f63666a7e203916e1b8af566cdc"

  strings:
    $s1 = "4@GRoUF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}