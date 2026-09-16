rule Virus_Autorun_Dump_Generic_PWS_WoW_EE1ADD03 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dump.Generic.PWS.WoW.EE1ADD03.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91489bdc9d6d8fed7a69dc143d4b6a195b0cc101e609c02d277b76e126b23e78"

  strings:
    $s1 = " \"Designed for Windows 98\" " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}