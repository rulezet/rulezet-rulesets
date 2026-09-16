rule Virus_Hijack_Gen_Trojan_ShellObject_x8Z_a4IIY9p_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.x8Z@a4IIY9p_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "910eba837289329642ac8c7eb6dbfe44e466066541f55a1465482fe65c4a90d6"

  strings:
    $s1 = "iSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}