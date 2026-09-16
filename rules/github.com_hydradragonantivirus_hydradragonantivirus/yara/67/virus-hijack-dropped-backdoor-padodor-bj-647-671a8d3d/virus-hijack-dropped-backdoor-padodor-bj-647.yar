rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_647 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_647.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "acbe065cdbb06e542ba03874ed25c18eca551f0e95831c9a3d96fae2200792a9"

  strings:
    $s1 = "%and services at the list price in effect at the " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}