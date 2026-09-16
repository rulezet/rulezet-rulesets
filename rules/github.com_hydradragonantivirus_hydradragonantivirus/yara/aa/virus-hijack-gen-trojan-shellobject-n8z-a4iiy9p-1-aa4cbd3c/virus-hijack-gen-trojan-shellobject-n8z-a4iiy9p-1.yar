rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "317611ad622b9526451df56572701803ab825e6b99b4201e154daadbdf7dee06"

  strings:
    $s1 = "PSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}