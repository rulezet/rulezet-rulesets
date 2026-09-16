rule Trojan_Danger_Trojan_GenericKD_72304918_166 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_166.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b28d669b1619fdea5314e744a1fc464329f8d96e543a69d099feff7c9cda93f"

  strings:
    $s1 = "Microsoft Office PowerPoint 2007.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}