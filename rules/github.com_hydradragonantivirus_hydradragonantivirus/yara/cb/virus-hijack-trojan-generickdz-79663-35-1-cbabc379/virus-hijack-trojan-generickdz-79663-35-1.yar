rule Virus_Hijack_Trojan_GenericKDZ_79663_35_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_35_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49b43a2f40883c94e1a8418fdeb57d6538cc69e66d11d626c99fe397aeaf698a"

  strings:
    $s1 = "<vasE>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}