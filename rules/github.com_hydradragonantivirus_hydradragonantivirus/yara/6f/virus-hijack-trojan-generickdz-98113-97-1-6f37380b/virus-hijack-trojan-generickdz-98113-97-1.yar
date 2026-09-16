rule Virus_Hijack_Trojan_GenericKDZ_98113_97_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_97_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7659bffc3240345d8baac2a2b5146897563f57d445154c75a5367b608573fa6f"

  strings:
    $s1 = "U&DEmY" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}