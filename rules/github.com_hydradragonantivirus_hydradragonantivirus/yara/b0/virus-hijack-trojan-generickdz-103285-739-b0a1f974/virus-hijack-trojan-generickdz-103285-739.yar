rule Virus_Hijack_Trojan_GenericKDZ_103285_739 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_739.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d197b8cb4c841343ffd2fcfb6fb248dc7d9b954936f3ca93c0d161dccb14ba77"

  strings:
    $s1 = "mUsk;-Tk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}