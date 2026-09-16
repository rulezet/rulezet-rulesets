rule Virus_Hijack_Dropped_Trojan_Peed_Gen_21 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Trojan.Peed.Gen_21.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "78ed786a0cab2535bfad067d312efb75dc735d51aa1a009621edd3c8a206e05d"

  strings:
    $s1 = "ULUA!{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}