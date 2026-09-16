rule Virus_Infector_Win32_Expiro_Gen_7_172 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_172.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce18deda771487ba99d5d560e1e8323e0039c173b99d8d4eb2c272d52a1ead21"

  strings:
    $s1 = "crUm!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}