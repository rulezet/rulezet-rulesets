rule Trojan_Danger_Trojan_GenericKD_72853156_394_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_394_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3049dad2e580d6320e921959daba2280ffd6a3b6e2d3a5c1cce23c59e22cca82"

  strings:
    $s1 = "The ordinal %d could not be located in the DLL %s." fullword ascii
    $s2 = "The procedure %s could not be located in the DLL %s." fullword ascii
    $s3 = "Application corrupt." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}