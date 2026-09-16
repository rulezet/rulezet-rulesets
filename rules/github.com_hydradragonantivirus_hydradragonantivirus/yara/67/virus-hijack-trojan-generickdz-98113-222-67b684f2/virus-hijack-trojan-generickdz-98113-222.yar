rule Virus_Hijack_Trojan_GenericKDZ_98113_222 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_222.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87beb97575e9a9de1dfaaba786def26d4e0c7858be2de4659b2e214b99f29b52"

  strings:
    $s1 = "p-4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}