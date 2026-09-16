rule Virus_Hijack_Trojan_GenericKDZ_103545_21_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_21_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2756c54528291b6773b0a72441cb54fdeef68ff731d33328e9b25e66924c8f70"

  strings:
    $s1 = "DARK>+" fullword ascii
    $s2 = "!secT B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}