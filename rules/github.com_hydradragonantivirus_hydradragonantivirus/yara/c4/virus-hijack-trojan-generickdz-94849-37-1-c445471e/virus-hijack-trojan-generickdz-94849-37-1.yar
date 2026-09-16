rule Virus_Hijack_Trojan_GenericKDZ_94849_37_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f368a803c4213649d5691469beb0488e8c03cb55ee9c41fc408c5d578971cf1f"

  strings:
    $s1 = "}roUE)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}