rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "899110768626de1a03145e184cb719e2b2685cd12829738d5ca91225d08b870f"

  strings:
    $s1 = "p4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}