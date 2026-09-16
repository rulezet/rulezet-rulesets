rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20f3cb5fae5df428022ba9e9a830d10581322dd2cb6bbdbbb019e783f07e5979"

  strings:
    $s1 = "<Module>{88D7EBF3-CA8A-40CE-8807-B24E8861EED8}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}