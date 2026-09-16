rule Virus_Hijack_Gen_Trojan_ShellObject_i0Y_aKzulAn_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i0Y@aKzulAn_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc6c4d24900b4363f1b0ea5954b831eedac2ecc011164208ac5b7bbb461db40f"

  strings:
    $s1 = "TUNg%)=f" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}