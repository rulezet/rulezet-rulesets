rule Virus_Hijack_Trojan_GenericKDZ_103285_283 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_283.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bb4d872346d816033a1cbda67675a4ed841e07e2b6fafbbe65a28d9ecf202184"

  strings:
    $s1 = "*available at go.microsoft.com/fwlink/?linkid=245497 to the AAA. You agree to commence arbitration only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}