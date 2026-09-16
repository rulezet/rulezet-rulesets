rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_8 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_8.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f31e7ed123352be6956cb9b0c6f07341a5a7f38348f21802c2e00b45eb85b497"

  strings:
    $s1 = "'/Professional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}