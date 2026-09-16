rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_12 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_12.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "84d1e009c213e0b316c18bca51f345983489db945120c3a9add4ff9908c3d4b6"

  strings:
    $s1 = "qu4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}