rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiKV3eh_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiKV3eh_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f67760a45e3aae45578a5a6affd8bb1ff1cdfe977c8d8cbb09e4d03ba18907d3"

  strings:
    $s1 = "8Subscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}