rule Virus_Hijack_Gen_Trojan_ShellObject_x8Z_a4IIY9p_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.x8Z@a4IIY9p_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "290da5577c2e960b76c66ba2adfd98a527107208695f059dd2358ddab853f5fd"

  strings:
    $s1 = "/[Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii
    $s2 = "/[Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device tha" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}