rule Virus_Hijack_Trojan_GenericKDZ_98113_105_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_105_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "369235ee9075440c25d8c49faed7f57d268b0f0bab55098406a4c4bdfa3f454c"

  strings:
    $s1 = ")[WaFf" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}