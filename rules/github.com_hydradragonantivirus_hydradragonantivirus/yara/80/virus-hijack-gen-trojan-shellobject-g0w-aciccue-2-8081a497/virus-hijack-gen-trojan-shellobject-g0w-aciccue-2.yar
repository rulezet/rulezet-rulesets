rule Virus_Hijack_Gen_Trojan_ShellObject_g0W_aCiCCue_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g0W@aCiCCue_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a70aa8ce8c4c04f5b7be24a9144351956110358ad4ec920c19189cdbbbe73a2"

  strings:
    $s1 = "The following software features use Internet protocols, which send to Microsoft (or" fullword ascii
    $s2 = "ACCEPT A" fullword ascii
    $s3 = "bgiving rise to the dispute, and the relief requested. You must send any Notice of Dispute by U.S. Mail to" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}