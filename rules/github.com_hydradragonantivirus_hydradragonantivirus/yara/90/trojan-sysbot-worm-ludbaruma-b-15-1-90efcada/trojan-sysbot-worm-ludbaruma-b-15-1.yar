rule Trojan_Sysbot_Worm_Ludbaruma_B_15_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Sysbot_Worm.Ludbaruma.B_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c96454828bf2fbd3fbba812d2c645657d0788e7d4f442d0f8c3a0914121e9b6"

  strings:
    $s1 = "Microsoft Office PowerPoint 2007.lnk" fullword ascii
    $s2 = "TRap?<RRRRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}