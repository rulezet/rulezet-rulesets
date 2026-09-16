rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "426abe66f233362e09b6a35e853a0a6ca205cfaf7d8424b1e0228fda288b3adf"

  strings:
    $s1 = "p4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}