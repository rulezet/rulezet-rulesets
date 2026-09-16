rule Virus_Hijack_Trojan_GenericKDZ_98113_54 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_54.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a2891368e7298c3e6e502f9b86a2332501db9b708de109a28ddc7c1fbcbd7430"

  strings:
    $s1 = "5your order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}