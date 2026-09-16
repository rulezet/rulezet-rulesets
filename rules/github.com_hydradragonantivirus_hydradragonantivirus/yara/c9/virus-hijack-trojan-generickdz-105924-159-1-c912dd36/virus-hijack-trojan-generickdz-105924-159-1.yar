rule Virus_Hijack_Trojan_GenericKDZ_105924_159_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_159_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eb180ad160549d0754076d4230617fdcb22666e1708a0b8d37c8886a9f554f3"

  strings:
    $s1 = "Fatnes impartiall enfranchise goggle countabl expectancie" fullword wide
    $s2 = "Blowe exorcism embellishin dopamin micturitio convic" fullword wide
    $s3 = "Clear filigre" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}