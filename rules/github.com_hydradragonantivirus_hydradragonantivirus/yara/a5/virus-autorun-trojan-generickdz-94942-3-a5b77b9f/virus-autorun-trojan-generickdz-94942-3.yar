rule Virus_Autorun_Trojan_GenericKDZ_94942_3 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Trojan.GenericKDZ.94942_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9916904c333abd1bad1b5c0bc7a44edca899721e603c61c74ae10cd620b1c4f3"

  strings:
    $s1 = "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.30.30704" fullword wide
    $s2 = "Microsoft Visual C++ 2015-2022 Redistributable (x86) - 14.30.3070" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}