rule Virus_Autorun_Gen_Variant_Genie_10_3 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Genie.10_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5f70b4133a9ac6d8f45eb8fb5a5707a5777cae63eef549e6b1d4245e9707279"

  strings:
    $s1 = "Microsoft Visual C++ 2012 Redistributable (x86) - 11.0.61030" fullword wide
    $s2 = ")Microsoft Root Certificate Aut" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}