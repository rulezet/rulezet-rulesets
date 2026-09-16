rule Virus_Infector_Win32_Expiro_Gen_7_97 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_97.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4e0b869cad35a381b56fee973302e2923d40520b6bafd5b838e84608c5e1981d"

  strings:
    $s1 = "YKT.[mEwl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}