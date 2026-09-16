rule Virus_Hijack_Trojan_GenericKDZ_98113_37_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_37_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dc6a37cfdd72fb4167d7ed27476b9680a398d8e7554915913c10f3d54ad6da25"

  strings:
    $s1 = "weet}5" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}