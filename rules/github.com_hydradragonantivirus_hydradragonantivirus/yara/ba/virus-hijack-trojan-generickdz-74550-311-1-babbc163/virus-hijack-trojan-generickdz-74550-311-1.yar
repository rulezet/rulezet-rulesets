rule Virus_Hijack_Trojan_GenericKDZ_74550_311_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_311_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8c719b25dd0d820d60ec49cf11b18667d72663815819024464debde20fec325"

  strings:
    $s1 = "AwNY?d" fullword ascii
    $s2 = "BRIm<|i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}