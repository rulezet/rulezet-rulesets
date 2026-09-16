rule Trojan_Danger_Trojan_GenericKD_67269844_3 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67269844_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0e15559fe9b213d8cdb59e21ef201cbf4177470a93ed1a84b3033a0e579ca578"

  strings:
    $s1 = "System Information.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}