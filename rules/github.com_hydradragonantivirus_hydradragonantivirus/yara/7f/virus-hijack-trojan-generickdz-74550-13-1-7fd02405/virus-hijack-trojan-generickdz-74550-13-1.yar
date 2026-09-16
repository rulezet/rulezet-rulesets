rule Virus_Hijack_Trojan_GenericKDZ_74550_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1884794d8e4423ce020eaf5d44af02880934c10abe4b852a841d0db70e040b9"

  strings:
    $s1 = "k(BEAN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}