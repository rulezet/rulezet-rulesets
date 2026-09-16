rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSb8tSc_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSb8tSc_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c7b8da5bf27af7e7d3a6a305919c76c2defb26c074cf07a61fe7bff4fb39dfa"

  strings:
    $s1 = "E:MOko" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}