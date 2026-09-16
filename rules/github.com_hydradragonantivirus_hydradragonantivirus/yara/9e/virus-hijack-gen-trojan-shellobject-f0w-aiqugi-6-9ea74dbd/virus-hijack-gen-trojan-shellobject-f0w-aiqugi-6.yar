rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65e31689264c728fae1b64924b28a35033eae03ca7748c367202911e17e37e89"

  strings:
    $s1 = "L34. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}