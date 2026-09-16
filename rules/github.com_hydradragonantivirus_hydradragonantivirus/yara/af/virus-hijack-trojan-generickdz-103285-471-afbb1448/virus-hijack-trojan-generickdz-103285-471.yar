rule Virus_Hijack_Trojan_GenericKDZ_103285_471 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_471.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "28c6109b51719980c1975b49b4850ac1b863006fe6ff182ffc03b27453ac5385"

  strings:
    $s1 = "mUsk;-Tk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}