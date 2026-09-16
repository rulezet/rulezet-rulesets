rule Virus_Hijack_Trojan_GenericKDZ_98113_179 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_179.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d5ebbb93a092f3ae1f336ef9740b880e1624ec8829ba41bd79715c02302abe57"

  strings:
    $s1 = "x-hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}