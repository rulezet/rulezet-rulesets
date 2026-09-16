rule Virus_Hijack_Trojan_GenericKDZ_98388_93_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_93_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c63f1bb3dd7704209e824921d7b3a531e05fa3372d65a440eeb36070f9357df"

  strings:
    $s1 = ";@z#sKEE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}