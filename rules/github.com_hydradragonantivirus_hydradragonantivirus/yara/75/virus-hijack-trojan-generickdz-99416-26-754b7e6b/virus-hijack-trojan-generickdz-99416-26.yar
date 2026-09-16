rule Virus_Hijack_Trojan_GenericKDZ_99416_26 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.99416_26.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1bbf4610f1b34a5c5333cef7ff9929ee9699fd8782e34187087ebcb14f297118"

  strings:
    $s1 = "JUser, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}