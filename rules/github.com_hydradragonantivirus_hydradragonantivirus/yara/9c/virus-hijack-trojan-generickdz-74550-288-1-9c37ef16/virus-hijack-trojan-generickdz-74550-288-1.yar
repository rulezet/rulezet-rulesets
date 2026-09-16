rule Virus_Hijack_Trojan_GenericKDZ_74550_288_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_288_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b334c3da1527afd0812c0cd6944237021fd1881e3b7c536e903f92ba4e356f21"

  strings:
    $s1 = "aMMA!a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}