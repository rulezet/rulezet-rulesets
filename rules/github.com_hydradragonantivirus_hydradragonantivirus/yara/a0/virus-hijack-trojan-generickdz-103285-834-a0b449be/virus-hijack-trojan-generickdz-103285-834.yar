rule Virus_Hijack_Trojan_GenericKDZ_103285_834 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_834.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6c0c34cff74445328e481e28eda65b015a592090fbdbe345725e87388984d3c"

  strings:
    $s1 = "The following software features use Internet protocols, which send to Microsoft (or" fullword ascii
    $s2 = "ACCEPT A" fullword ascii
    $s3 = "jgiving rise to the dispute, and the relief requested. You must send any Notice of Dispute by U.S. Mail to" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}