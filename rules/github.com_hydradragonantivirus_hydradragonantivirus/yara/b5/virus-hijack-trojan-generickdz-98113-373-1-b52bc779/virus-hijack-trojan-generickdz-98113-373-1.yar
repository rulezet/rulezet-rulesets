rule Virus_Hijack_Trojan_GenericKDZ_98113_373_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_373_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3655b7a496af3a754fb5b06e14926fbc7a3dbefc1f7de4eb93eb4eb2414771c1"

  strings:
    $s1 = "`{Room" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}