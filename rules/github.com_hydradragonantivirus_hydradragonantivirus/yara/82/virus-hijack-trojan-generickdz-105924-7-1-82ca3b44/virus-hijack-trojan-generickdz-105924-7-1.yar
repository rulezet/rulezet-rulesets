rule Virus_Hijack_Trojan_GenericKDZ_105924_7_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_7_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e3a8c2c988624dbfdb5faae36539d77e35d5ff09544eb873f34ad7bfc75639f"

  strings:
    $s1 = "EEly> n" fullword ascii
    $s2 = "}NOil?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}