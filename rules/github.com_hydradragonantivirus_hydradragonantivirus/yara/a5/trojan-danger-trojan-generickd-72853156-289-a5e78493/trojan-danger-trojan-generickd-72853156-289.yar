rule Trojan_Danger_Trojan_GenericKD_72853156_289 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_289.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e0dcc8f85b8ce9cb34906133db9ba2939e19bf2f750a2bfc2006a83610dde67a"

  strings:
    $s1 = "Task Manager.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}