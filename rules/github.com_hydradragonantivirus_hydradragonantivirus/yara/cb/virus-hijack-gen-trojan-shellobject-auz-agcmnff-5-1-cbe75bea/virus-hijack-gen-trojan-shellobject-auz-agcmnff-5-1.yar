rule Virus_Hijack_Gen_Trojan_ShellObject_AuZ_aGCmnff_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.AuZ@aGCmnff_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4f64c77f5485bf50a605ecc57856cdfb9c8334d6c0709c5ba9710697094e2d8"

  strings:
    $s1 = "This Installer database contains the logic and data required to install Microsoft Office Excel MUI (Italian) 2007." fullword ascii
    $s2 = "soft Visual" fullword ascii
    $s3 = "Microsoft Office Excel MUI (Italian) 2007" fullword ascii
    $s4 = "Installer, MSI, Database, Release" fullword ascii
    $s5 = "Windows Installer XML v2.0.3508.0 (candle/light)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}