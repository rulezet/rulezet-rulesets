rule Trojan_Danger_Trojan_GenericKD_72853156_489 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_489.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aa85319097b9e88cf4a60f4208189aebb11894d3db1477f8ccd15d796ce7067"

  strings:
    $s1 = "Python (command line).lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}