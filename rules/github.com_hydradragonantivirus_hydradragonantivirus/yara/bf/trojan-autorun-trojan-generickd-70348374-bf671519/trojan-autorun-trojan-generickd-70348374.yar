rule Trojan_Autorun_Trojan_GenericKD_70348374 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.70348374.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c6c8217e389634a6922b26b8b7446b4bf3947968b99a7be7c9dc14ec0d1e24d2"

  strings:
    $s1 = "About RootkitRevealer " fullword wide
    $s2 = "jVisible in Windows API, but not in MFT or directory index." fullword wide
    $s3 = "Copyright ? 1996-2006" fullword wide
    $s4 = "h::$DATA" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}