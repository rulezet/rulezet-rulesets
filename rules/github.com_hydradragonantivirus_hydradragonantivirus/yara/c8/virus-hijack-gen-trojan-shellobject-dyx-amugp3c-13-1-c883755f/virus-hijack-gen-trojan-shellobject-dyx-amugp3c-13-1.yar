rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_amUgp3c_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dde50d8945895372d45ddcf679709bb01f12ba9d31d1a2bc7e3aee092e83a9a7"

  strings:
    $s1 = "}$8S\"fiND" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}