rule Virus_Hijack_Trojan_GenericKDZ_98113_335_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_335_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ed23fa5835bcc8f2016fc554939292c989c690741e695e7e4c3b55b81a4fd21"

  strings:
    $s1 = "]EdGY " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}