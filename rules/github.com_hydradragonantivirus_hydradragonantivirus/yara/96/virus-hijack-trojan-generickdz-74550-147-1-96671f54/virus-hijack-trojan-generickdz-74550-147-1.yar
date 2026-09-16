rule Virus_Hijack_Trojan_GenericKDZ_74550_147_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_147_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "691b005666d8309c124df0793fac027e0008093948930a036bd42e4bf28517eb"

  strings:
    $s1 = "t#zYGa*S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}