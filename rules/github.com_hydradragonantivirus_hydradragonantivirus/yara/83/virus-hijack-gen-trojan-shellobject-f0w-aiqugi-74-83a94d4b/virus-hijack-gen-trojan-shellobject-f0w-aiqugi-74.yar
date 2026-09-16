rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_aiqugi_74 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@aiqugi_74.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d2f334993768bc5b6ea4cebef9e51b7e93742ac0b393a519fd9e75be0dcf071d"

  strings:
    $s1 = "@4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}