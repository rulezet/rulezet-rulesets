rule Virus_Hijack_Trojan_GenericKDZ_94849_28_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_28_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3a19803419a8fa2c1e860d97ace1e650eb3d1fe1fcf3f678626c6f63ac894c12"

  strings:
    $s1 = "`;TEnD" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}