rule Trojan_Hooker_Trojan_Generic_35968142 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Trojan.Generic.35968142.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3056c13c28acaa0dae9bcec60ea12db8cd99c2e9653c822313a19ffc4282249b"

  strings:
    $s1  = "Unempoisoned" fullword ascii
    $s2  = "Introversion" fullword ascii
    $s3  = "Alreadiness" fullword ascii
    $s4  = "Osseofibrous" fullword ascii
    $s5  = "Lemmitis" fullword ascii
    $s6  = "Hoodless" fullword ascii
    $s7  = "Miscegenate" fullword ascii
    $s8  = "Dyschroa" fullword ascii
    $s9  = "Unemulsified" fullword ascii
    $s10 = "Favoring" fullword ascii
    $s11 = "Harlotry" fullword ascii
    $s12 = "Frailejon" fullword ascii
    $s13 = "Sharnbud" fullword ascii
    $s14 = "Syndactylous" fullword ascii
    $s15 = "Gravamen" fullword ascii
    $s16 = "Wakefully" fullword wide
    $s17 = "Marital" fullword ascii
    $s18 = "Inwedged" fullword ascii
    $s19 = "Unthrushlike" fullword ascii
    $s20 = "Absinthol" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}