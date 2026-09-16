rule Trojan_Danger_Trojan_GenericKD_67166905_210 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_210.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8bf671713131b5e845ad8faf6483174c55c654ad88ffe709d4e31612e4a161db"

  strings:
    $s1 = "Microsoft Office Publisher 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}