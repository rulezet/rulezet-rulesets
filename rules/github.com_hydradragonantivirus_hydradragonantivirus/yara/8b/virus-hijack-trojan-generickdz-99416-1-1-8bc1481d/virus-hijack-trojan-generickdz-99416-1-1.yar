rule Virus_Hijack_Trojan_GenericKDZ_99416_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cfc395fcdd7733946cab8e16953149ceb0841758004e9bfcaf9a9aa57e6b2be5"

  strings:
    $s1 = "F\"tEmp" fullword ascii
    $s2 = "!-@WOPs" fullword ascii
    $s3 = "O&bond" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}