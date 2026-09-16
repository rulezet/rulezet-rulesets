rule Trojan_Danger_Trojan_GenericKD_67064203_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67064203_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c633d67e495022688bf2ff1f2a32a3efa0b1cd45d6313ce4966ef1a7071868"

  strings:
    $s1 = "MSubscriber: is defined as (a) a working telephone number for all wireline devices; (b) a portable handset or paging device that" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}