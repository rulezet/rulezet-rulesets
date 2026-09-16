rule Virus_Hijack_Gen_Trojan_ShellObject_gCZ_aCmWGmd_31 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gCZ@aCmWGmd_31.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66159a296ef72ed817e955a12145502e0b839c497b460621c8a6bc144f4121ea"

  strings:
    $s1 = "Illuminist" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}