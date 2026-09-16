rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_781_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_781_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84d721511317155c72daf902df0920478243eb7941690806471708f778acc339"

  strings:
    $s1 = "ramiferous" fullword wide
    $s2 = "Tattooment" fullword wide
    $s3 = "Gnathonize" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}