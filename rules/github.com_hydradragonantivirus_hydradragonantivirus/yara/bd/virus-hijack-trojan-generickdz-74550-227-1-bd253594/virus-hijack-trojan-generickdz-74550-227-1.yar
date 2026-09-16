rule Virus_Hijack_Trojan_GenericKDZ_74550_227_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8f2fbbe46ed17497341d9f25f55b35ba0c4242d16a28371fbeddf6750ced15a"

  strings:
    $s1 = ",WivE(" fullword ascii
    $s2 = "DraB5IeF" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}