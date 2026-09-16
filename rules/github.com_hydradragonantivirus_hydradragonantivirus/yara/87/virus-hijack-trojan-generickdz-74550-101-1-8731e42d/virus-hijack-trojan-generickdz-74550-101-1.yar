rule Virus_Hijack_Trojan_GenericKDZ_74550_101_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bee30af95701efb4a6ea498f61566039b8ab58b27dde70d2ad6bb6a6e46338a"

  strings:
    $s1 = "anUS]0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}