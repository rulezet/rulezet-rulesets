rule Virus_Sysbot_Trojan_GenericKDZ_94923_12_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Trojan.GenericKDZ.94923_12_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bc8b49458d5fb7d228bb2541189e2de7122f6819087c7eb00fcf215bdcaf7c7"

  strings:
    $x1 = "<?xml version=\"1.0\" encoding=\"utf-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersio" ascii
    $s2 = "Nais!sv4" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}