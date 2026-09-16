rule Trojan_Danger_Trojan_GenericKD_67166905_211_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_211_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b41ec9e21ca977c25e432819407606f4ef0a9807ffbb99463f3cacc1531f54f"

  strings:
    $s1 = "ybdispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}