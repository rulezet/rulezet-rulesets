rule Virus_Hijack_Trojan_GenericKDZ_105924_566_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_566_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f51621574bba96ed5a6d4df506e5b32d217e69f11d735c7d9c9c2a85e7a0d7cc"

  strings:
    $s1 = "l!Iced" fullword ascii
    $s2 = "^&gAwm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}