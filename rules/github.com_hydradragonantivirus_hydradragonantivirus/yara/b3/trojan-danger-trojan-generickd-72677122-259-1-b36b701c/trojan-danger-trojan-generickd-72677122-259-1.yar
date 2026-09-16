rule Trojan_Danger_Trojan_GenericKD_72677122_259_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_259_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdbd97c19aefaeb0a9604c2bd42dab32a41d4fee42b6cae8d4eac5c62ee5746f"

  strings:
    $s1 = "Failed to create status bar" fullword ascii
    $s2 = "View Bar" fullword ascii
    $s3 = "Infra ERP/WinPower" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}