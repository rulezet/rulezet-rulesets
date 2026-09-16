rule Virus_Hijack_Trojan_GenericKDZ_74550_224_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_224_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f0901d73a3abae6d620a5c201c6a6617d08a0883aa810b3da565974e9b197e6f"

  strings:
    $s1 = "QuAB%tj" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}