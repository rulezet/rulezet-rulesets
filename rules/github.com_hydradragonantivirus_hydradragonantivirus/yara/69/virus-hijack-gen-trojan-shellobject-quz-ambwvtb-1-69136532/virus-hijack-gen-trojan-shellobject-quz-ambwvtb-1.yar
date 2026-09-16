rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_amBwvTb_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@amBwvTb_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d81521a2e82b618095e88bf77030a9de0cbf151c8317dd802c84a3d4942981b"

  strings:
    $s1 = "naZE;D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}