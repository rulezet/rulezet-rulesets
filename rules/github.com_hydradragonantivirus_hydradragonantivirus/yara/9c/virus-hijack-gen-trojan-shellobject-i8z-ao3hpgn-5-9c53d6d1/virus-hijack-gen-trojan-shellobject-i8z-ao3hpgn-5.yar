rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8d74a63b9cb72b3e264d0057876202585690a77e2e68eee9e359a46ee53441b3"

  strings:
    $s1 = "3Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}