rule Virus_Hijack_Trojan_GenericKDZ_105924_516_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_516_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "694a288f3f94eda188d184b180a94e0fc367c8cdc14f0a60cf9777dffe6e8343"

  strings:
    $s1 = "<!DarI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}