rule Virus_Infector_Win32_Expiro_Gen_7_49 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_49.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d51d97fa690ebd96791db2608dfc4faaffc1392eb74cfb9f4bb5da913172633d"

  strings:
    $s1 = "dARE#p" fullword ascii
    $s2 = "\"MuZZ%Z" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}