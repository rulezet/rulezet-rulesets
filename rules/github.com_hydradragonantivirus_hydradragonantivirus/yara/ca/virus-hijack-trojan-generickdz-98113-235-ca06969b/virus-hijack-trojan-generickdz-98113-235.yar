rule Virus_Hijack_Trojan_GenericKDZ_98113_235 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_235.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "15530d6c56c611d55b4079ed40e2afd55979fe785cd3832923e9e8f3550966b2"

  strings:
    $s1 = "ahundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}