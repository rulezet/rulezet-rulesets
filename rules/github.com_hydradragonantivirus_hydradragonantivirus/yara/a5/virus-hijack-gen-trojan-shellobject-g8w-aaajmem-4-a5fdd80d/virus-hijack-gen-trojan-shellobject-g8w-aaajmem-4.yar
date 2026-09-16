rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_4 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2998a0f05cae3f6f5cb8a861dbcf40d2499470f4f29a8210b021d6deef6b30fd"

  strings:
    $s1 = "(=What if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}