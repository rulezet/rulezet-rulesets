rule Trojan_Danger_Trojan_GenericKD_72853156_180_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_180_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89e435189bb64fd956726b8aa89d64d7a535e8c689a23857adb331e1549ad820"

  strings:
    $s1 = "BOLE<a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}