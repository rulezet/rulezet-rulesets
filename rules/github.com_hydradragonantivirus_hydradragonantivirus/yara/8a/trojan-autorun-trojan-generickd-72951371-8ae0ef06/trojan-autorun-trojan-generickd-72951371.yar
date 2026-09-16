rule Trojan_Autorun_Trojan_GenericKD_72951371 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72951371.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cf5f7bb641df756bad6375ea918bb2f5edcfa8d3e66a6ffcb92614b914dda08"

  strings:
    $s1 = "[Visible in Windows API, but not in MFT or directory index." fullword wide
    $s2 = "Y::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}