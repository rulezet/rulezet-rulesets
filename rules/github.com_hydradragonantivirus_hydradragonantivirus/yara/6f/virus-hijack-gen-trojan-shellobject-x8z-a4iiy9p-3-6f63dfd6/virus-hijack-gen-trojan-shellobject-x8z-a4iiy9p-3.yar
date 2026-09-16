rule Virus_Hijack_Gen_Trojan_ShellObject_x8Z_a4IIY9p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.x8Z@a4IIY9p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c039442536fe4a756bc9511c7e627ca3025bdf6e5ba56424528cf55eb94ae98"

  strings:
    $s1 = "9.Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "9.Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}