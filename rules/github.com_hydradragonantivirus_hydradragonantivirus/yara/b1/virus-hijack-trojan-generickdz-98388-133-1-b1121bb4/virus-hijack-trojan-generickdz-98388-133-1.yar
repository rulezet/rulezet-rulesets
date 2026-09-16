rule Virus_Hijack_Trojan_GenericKDZ_98388_133_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_133_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "26f9522cf2acbd7a6cf78b16a999dd33a7dd7e6caf0c3c4047ab9c38fc853ac3"

  strings:
    $s1 = "Pa:gUSS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}