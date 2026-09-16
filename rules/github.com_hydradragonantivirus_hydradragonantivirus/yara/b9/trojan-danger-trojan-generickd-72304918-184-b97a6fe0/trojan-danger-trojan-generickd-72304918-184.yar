rule Trojan_Danger_Trojan_GenericKD_72304918_184 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_184.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4bbdbe5c2c60999cbf59a09ea8a8103d10adebfa2c5da71ae4625de020c1280f"

  strings:
    $s1 = "Interactive Ruby.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}