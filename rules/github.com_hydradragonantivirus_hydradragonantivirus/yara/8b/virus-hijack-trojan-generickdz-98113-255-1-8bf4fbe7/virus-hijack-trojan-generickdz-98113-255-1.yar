rule Virus_Hijack_Trojan_GenericKDZ_98113_255_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_255_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3d256bf06e7de4ff29a3d60b6c7ba6a98129a7677b04ed5e3f798ec897af11b"

  strings:
    $s1 = "F;lOoK" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}