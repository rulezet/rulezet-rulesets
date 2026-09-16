rule Virus_Hijack_Trojan_GenericKDZ_74550_113_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_113_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a78e978a851208e313ce8811bad02959894df80604805e23a3f621183aced1c3"

  strings:
    $s1 = "?&bOCE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}