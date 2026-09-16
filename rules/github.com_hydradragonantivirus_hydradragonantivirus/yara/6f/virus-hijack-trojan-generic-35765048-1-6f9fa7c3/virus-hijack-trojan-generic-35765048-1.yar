rule Virus_Hijack_Trojan_Generic_35765048_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Generic.35765048_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "350649e4c1f2e3a1bc1fdb8e8f15fd10e692b5562e57100f91f19029d486e802"

  strings:
    $s1 = ")^!sHER" fullword ascii
    $s2 = "U?bAnE,KQ" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}