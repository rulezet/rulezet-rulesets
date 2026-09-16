rule Virus_Hijack_Trojan_GenericKDZ_98113_70 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_70.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2172c8838da53dc6804e3e325d1eb534af09ca6be923c5c49e5882c6c4f5f4a6"

  strings:
    $s1 = "_(4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}