rule Virus_Hijack_Gen_Trojan_ShellObject_i0Z_aiqugi_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Z@aiqugi_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d8009e8a3fcf22e6737df8e392b532dd357c6d7d88626aa2e77dbc000a9c1cb"

  strings:
    $s1 = "|4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}