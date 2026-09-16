rule Virus_Hijack_Trojan_GenericKDZ_98113_102 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_102.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43cb75227a026f098adbdf744430baa7336e97909dd0fb070151e3bb29f1c7d3"

  strings:
    $s1 = "yby different names such as reseller, distributor" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}