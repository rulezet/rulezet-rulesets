rule Virus_Hijack_Trojan_GenericKDZ_74550_65_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_65_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8063e3ccbe6ad2466ce4d123b9b5e2aea75b93f2a36de4b94c335ab2acb6870f"

  strings:
    $s1 = "WoLf:z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}