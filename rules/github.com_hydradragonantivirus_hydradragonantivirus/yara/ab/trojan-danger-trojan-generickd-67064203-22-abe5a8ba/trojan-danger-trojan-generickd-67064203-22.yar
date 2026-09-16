rule Trojan_Danger_Trojan_GenericKD_67064203_22 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67064203_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b375fccab62f4e9022956fdb2425e35a37353c53b71896479e50b4e32aedcd2"

  strings:
    $s1 = "Microsoft Office PowerPoint 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}