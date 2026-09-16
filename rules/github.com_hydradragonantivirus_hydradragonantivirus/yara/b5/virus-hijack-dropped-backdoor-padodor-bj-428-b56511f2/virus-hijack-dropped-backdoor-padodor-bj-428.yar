rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_428 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_428.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9c9b28ec0357e1e6c32a906b131cdf37ebd03414ebb89720687e334c553fa61"

  strings:
    $s1 = "4are a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}