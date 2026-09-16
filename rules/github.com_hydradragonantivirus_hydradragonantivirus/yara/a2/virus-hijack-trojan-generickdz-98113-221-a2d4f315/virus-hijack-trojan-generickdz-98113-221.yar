rule Virus_Hijack_Trojan_GenericKDZ_98113_221 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_221.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96691607b00bb6e5cb9ac5d9f5aec2ae4ede69b957313d23c117bde7357c9260"

  strings:
    $s1 = "Xw4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}