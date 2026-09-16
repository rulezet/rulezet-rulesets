rule Virus_Hijack_Gen_Trojan_ShellObject_dGW_aulKiep_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGW@aulKiep_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "61907d04aa7e8ad2a17a1d17025f266040f440982c5884d711626b42f8413f1d"

  strings:
    $s1 = "_={sURe" fullword ascii
    $s2 = "SaWN&8" fullword ascii
    $s3 = "7*mAbi" fullword ascii
    $s4 = "noEl@B" fullword ascii
    $s5 = "SpUD{/" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}