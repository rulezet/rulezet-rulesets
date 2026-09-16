rule Virus_Hijack_Trojan_GenericKDZ_94849_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.94849_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c42860bc435a21e30b17b3dc40a914ec837b25ddb46f32b8f117341c7e2574bc"

  strings:
    $s1 = ":RINu##lehr" fullword ascii
    $s2 = "b!WhyO%" fullword ascii
    $s3 = "^,GIEN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}