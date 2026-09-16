rule Trojan_Danger_Trojan_GenericKD_72677122_187_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_187_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bf8f86ceb16fcb04ee37f9ecc73859ea97d2163878e2281bb996c52c20ca78"

  strings:
    $s1 = "Encode:'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}