rule Virus_Hijack_Trojan_GenericKDZ_105924_101_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_101_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "11c97c62fe70db824fdf45a968219d3c632311b8aa2fd7a4df9297c093856dd6"

  strings:
    $s1 = "ScAN@)" fullword ascii
    $s2 = "(C`QUet" fullword ascii
    $s3 = "Y*aMBA" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}