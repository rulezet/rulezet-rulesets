rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aCMzZah_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aCMzZah_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "74a3d8f261ef737c644a01142892accb3437665cd9e98c15aaa751414b64f799"

  strings:
    $s1 = "i>orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}