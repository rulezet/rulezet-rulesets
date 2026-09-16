rule Virus_Hijack_Trojan_GenericKDZ_98113_325 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_325.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e9d402df14abc80145f3cac908df854c076b918613b577b450bf36a559548d5"

  strings:
    $s1 = "S}pepo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}