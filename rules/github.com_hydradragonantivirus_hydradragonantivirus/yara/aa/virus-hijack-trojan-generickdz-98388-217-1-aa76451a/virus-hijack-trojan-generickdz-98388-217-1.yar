rule Virus_Hijack_Trojan_GenericKDZ_98388_217_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_217_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5e2cafb6244eaea25e3d7b7693ff43c96729ab6423492851fa6c7b07306896e"

  strings:
    $s1 = "M{hive" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}