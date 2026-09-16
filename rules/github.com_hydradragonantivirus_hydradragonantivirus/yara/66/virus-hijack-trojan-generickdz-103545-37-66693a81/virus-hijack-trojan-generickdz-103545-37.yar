rule Virus_Hijack_Trojan_GenericKDZ_103545_37 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_37.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b130c9b3e40244a763cdb5dcdb94e86860ec07c48493f690a3ed70bd760fe8f"

  strings:
    $s1 = ",software features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}