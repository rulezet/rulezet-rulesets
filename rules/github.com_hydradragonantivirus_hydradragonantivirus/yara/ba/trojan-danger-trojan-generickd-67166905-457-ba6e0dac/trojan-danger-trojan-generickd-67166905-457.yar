rule Trojan_Danger_Trojan_GenericKD_67166905_457 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_457.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33b95d744655bd624e4453d17b839a65d78c1bc5c344abd0352d1c3061ab5353"

  strings:
    $s1 = "System Information.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}