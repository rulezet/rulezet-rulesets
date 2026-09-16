rule Virus_Hijack_Trojan_GenericKDZ_103545_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1be43ace5b9c1cf3d450566fd6c4dda13a7c1a1b19cbdcb069248fb9c775de1e"

  strings:
    $s1 = "tlsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}