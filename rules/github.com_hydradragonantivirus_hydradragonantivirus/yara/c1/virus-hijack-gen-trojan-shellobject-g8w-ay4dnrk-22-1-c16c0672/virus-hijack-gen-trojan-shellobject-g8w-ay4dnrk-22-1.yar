rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_ay4DNrk_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@ay4DNrk_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19739628e3818d3c5dd7cd3fb28a0f9ecdfa8da12d09489741e384dc89c49400"

  strings:
    $s1 = "Posthouse" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}