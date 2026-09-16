rule Virus_Hijack_Trojan_GenericKDZ_74550_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b7045b258b633c844956e941aea3137d1cddfe52c89c2bce07ea34cfd93a52e"

  strings:
    $s1 = "-}COre" fullword ascii
    $s2 = "$FLAN:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}