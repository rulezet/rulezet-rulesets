rule Trojan_Danger_Trojan_GenericKD_72853156_182 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_182.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60f22b26d15922650ab2d5f734325e64d2d9639e8da71b45c40edbb842ce7f1a"

  strings:
    $s1 = "^L'Wbad allocation" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}