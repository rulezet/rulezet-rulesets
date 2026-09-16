rule Trojan_Danger_Trojan_GenericKD_72853156_185_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_185_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29ea50c39a7892a1cf83c87d0ec09f8d7d5821c824176df0e8edd0cc3700de92"

  strings:
    $s1 = "Copyright  Beautyd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}