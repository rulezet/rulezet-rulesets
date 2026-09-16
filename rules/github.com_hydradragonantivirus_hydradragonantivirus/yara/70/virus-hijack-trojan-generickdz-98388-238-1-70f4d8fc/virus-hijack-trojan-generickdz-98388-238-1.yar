rule Virus_Hijack_Trojan_GenericKDZ_98388_238_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_238_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a329c0f3bb8a0e2b6d12d36f4996cfb22be3f28ddf6ff99ae7251840b9e93f3f"

  strings:
    $s1 = "BikH?0G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}