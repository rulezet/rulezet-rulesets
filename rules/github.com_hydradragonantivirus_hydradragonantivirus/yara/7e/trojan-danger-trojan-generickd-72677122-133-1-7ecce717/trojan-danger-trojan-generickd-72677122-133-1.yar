rule Trojan_Danger_Trojan_GenericKD_72677122_133_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_133_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb551447ac8f5448ee77a3e892511d7cb676efec91d81309916803d50c87973c"

  strings:
    $s1 = "at,Jiti" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}