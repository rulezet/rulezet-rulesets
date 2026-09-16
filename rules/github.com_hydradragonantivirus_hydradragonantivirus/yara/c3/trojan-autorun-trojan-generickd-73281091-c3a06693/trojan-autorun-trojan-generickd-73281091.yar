rule Trojan_Autorun_Trojan_GenericKD_73281091 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.73281091.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "330a66d646aebaf21855ea767d931d6a1b6c1a151add8bacf45b126ba9a58b3a"

  strings:
    $s1 = "}Visible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "z::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}