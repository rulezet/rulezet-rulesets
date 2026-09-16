rule Trojan_Danger_Trojan_GenericKD_67166905_139 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_139.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aef295e50ab069de720a1b24e695d9d3c50fb366f196f20b0d12d7842447f43b"

  strings:
    $s1 = "System Information.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}