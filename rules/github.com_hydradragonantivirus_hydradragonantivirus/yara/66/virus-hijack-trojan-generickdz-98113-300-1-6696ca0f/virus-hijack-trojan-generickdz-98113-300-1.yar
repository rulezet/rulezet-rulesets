rule Virus_Hijack_Trojan_GenericKDZ_98113_300_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_300_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d0eb3d9aefde71371b48e1ebd776595cc1d230f76bce3e220d061e5c9a5ab19"

  strings:
    $s1 = "GrapY&i" fullword ascii
    $s2 = "d*ThuG" fullword ascii
    $s3 = "[@niPa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}