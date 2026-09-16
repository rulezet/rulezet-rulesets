rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aiqugi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aiqugi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5382fd83f2a29f5349c3a7262fd52302e7bb36d06b82045edd9486ccfeb24eab"

  strings:
    $s1 = "nA4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}