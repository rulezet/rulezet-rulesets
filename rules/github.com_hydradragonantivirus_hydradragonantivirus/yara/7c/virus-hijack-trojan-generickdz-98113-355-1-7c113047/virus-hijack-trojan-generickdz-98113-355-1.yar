rule Virus_Hijack_Trojan_GenericKDZ_98113_355_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_355_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22f3fe168b0a8bfaf7ec7703449f3154241a83434e3103e26447f2c363d213b4"

  strings:
    $s1 = "3(X`slUR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}