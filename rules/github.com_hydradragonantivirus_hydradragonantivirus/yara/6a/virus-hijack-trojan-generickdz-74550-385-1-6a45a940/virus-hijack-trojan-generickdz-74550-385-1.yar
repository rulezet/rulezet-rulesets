rule Virus_Hijack_Trojan_GenericKDZ_74550_385_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_385_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "eb5563cf26c72f1357b062e8120cb28cdf111ca5d653ba70e5774e4a032db0b4"

  strings:
    $s1 = "~%bota" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}