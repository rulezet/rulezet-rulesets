rule Virus_Hijack_Trojan_GenericKDZ_74550_347_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_347_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ea9feba007beb631effb6b2bf665a6968415eaa73b12726cfd0821ba5b12c03"

  strings:
    $s1 = "l^l wREN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}