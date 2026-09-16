rule Virus_Hijack_Trojan_GenericKDZ_98113_156_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_156_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b088452a5e506d71cae5e6169a7e2aa05e88f1ae18c6fb1f76baa90f8d916c40"

  strings:
    $s1 = "%>chIp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}