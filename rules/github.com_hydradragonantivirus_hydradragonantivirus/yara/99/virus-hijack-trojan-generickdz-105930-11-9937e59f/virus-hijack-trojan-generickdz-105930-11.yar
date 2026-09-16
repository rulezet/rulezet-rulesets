rule Virus_Hijack_Trojan_GenericKDZ_105930_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105930_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e85850d103cdcfd0c333bcd6b0788e8fd08a49096b327edfbf2617b8d416067e"

  strings:
    $s1 = "yOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}