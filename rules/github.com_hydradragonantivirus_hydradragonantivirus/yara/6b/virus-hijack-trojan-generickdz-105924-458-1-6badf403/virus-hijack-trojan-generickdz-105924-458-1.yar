rule Virus_Hijack_Trojan_GenericKDZ_105924_458_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_458_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "005f6e3ccbc51a3b106251fedce8011d2ba5a4a852a780193809b48fc3df53fb"

  strings:
    $s1 = "# MeRO{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}