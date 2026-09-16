rule Virus_Hijack_Trojan_GenericKDZ_105924_404_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_404_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07f8f9a79220b237d1cb259144a7491760272710b813ee94f4002b4df7066621"

  strings:
    $s1 = "DORY`~" fullword ascii
    $s2 = "load(}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}