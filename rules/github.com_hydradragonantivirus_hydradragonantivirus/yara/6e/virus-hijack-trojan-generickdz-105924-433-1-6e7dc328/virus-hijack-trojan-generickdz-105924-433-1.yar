rule Virus_Hijack_Trojan_GenericKDZ_105924_433_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_433_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "602021925d2615b956cd2ac33deb6af306c0e26a93707a3606f2725002c187e9"

  strings:
    $s1 = "wBO{GaVe" fullword ascii
    $s2 = ":rP?GEet," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}