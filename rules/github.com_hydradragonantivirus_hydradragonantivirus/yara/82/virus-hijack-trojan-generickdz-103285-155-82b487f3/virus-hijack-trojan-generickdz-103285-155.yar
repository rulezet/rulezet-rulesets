rule Virus_Hijack_Trojan_GenericKDZ_103285_155 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_155.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "720a73fb63a88f326a94e0ee7ea7d68ba683281e23a70d6984998e83a07057b3"

  strings:
    $s1 = "/available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}