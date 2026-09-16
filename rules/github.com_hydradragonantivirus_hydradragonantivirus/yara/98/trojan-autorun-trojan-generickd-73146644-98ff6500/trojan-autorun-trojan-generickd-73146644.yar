rule Trojan_Autorun_Trojan_GenericKD_73146644 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.73146644.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0340bf518edbb125861b256d48d0ea0d0299f1e59925d9a3a83542de7df52805"

  strings:
    $s1 = "Visible in Windows API, but not in MFT or directory index." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}