rule Virus_Infector_Win32_Expiro_Gen_7_48 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_48.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05fc20d9d523406d7aa08c44843529aedaa96bcae2d2c6911f7466aefc2bd205"

  strings:
    $s1 = "h>SuDs" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}