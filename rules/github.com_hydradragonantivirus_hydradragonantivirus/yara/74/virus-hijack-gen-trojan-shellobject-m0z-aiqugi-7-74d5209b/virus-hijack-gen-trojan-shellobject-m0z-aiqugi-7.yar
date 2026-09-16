rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e6d574ef4c6923d6261e585e9c458486bcfce9e414b1da09383785c01d8bd7da"

  strings:
    $s1 = "@4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}