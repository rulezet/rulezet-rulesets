rule Virus_Hijack_Trojan_GenericKDZ_98113_189 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_189.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bcd941918a44734894f43473b4dfc8c74467a202aa255ecf7f24973e1895d17e"

  strings:
    $s1 = "D4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}