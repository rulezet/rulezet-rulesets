rule Trojan_Danger_Trojan_GenericKD_72677122_275_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_275_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ec11db86992962a76aaf3e6532843da9f1214159957ae8b785c34fbed33c6b8"

  strings:
    $s1 = "@Avast Browser" fullword wide
    $s2 = "Avast Browser On Demand" fullword wide
    $s3 = "(C) 2017-2024 Gen Digital Inc." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}