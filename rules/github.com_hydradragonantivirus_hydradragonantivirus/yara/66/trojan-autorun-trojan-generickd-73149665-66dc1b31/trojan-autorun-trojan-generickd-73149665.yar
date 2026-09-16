rule Trojan_Autorun_Trojan_GenericKD_73149665 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.73149665.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec22cd7644dcd27c1adb8e80d5329e131585d3f6fc73d630a35198757aea1ff4"

  strings:
    $s1 = "Visible in Windows API, but not in MFT or directory index." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}