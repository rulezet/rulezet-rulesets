rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_amCvSwc_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@amCvSwc_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c15a3fe9f6d80a9d80289eb1d163daa1076ccef7f6ff5efa9e067ef3716c917"

  strings:
    $s1 = "oofY#<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}