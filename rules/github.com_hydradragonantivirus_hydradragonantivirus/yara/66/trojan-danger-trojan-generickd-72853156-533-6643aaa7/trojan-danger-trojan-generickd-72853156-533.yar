rule Trojan_Danger_Trojan_GenericKD_72853156_533 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_533.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b80d9509610781cfa200200fb6e8de520d71acf4f97742d1ecc0064ce88d241"

  strings:
    $s1 = "Python (command line).lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}