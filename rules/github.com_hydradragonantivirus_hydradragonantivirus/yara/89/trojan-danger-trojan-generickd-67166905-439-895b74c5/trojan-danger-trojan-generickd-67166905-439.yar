rule Trojan_Danger_Trojan_GenericKD_67166905_439 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_439.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fed8ca6f61af6839308423c64e289427d8c1871598fbad55660fae4a112f872b"

  strings:
    $s1 = "g]dhai]h" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}