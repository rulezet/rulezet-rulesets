rule Virus_Hijack_Trojan_GenericKDZ_79663_92_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.79663_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1e19c2197af332bd6953e73aa89551fbdfb23d1372fcbe1e0215a190ce07eef0"

  strings:
    $s1 = "st/@Work" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}