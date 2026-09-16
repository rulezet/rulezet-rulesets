rule Virus_Hijack_Trojan_GenericKDZ_105924_512_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_512_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7402a71c762deeeaeecebaeb2c602b4bd239e447f20b79c5b760107b1520fce"

  strings:
    $s1 = "j}hEaf" fullword ascii
    $s2 = ":!CUrn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}