rule Virus_Hijack_Trojan_GenericKDZ_98388_48_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_48_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5990989b82b402a6eba61d99f3db702c0f7140550839b9d551697fb6265e260"

  strings:
    $s1 = "heWt;N" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}