rule Virus_Hijack_Trojan_GenericKDZ_99416_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4915773b6cb994edaee42af34f8db1482876266bf23868378f38ee276c594f0"

  strings:
    $s1 = "%gUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}