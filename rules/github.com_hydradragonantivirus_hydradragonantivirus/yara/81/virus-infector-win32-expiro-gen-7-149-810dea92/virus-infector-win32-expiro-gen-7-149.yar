rule Virus_Infector_Win32_Expiro_Gen_7_149 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_149.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f27fcfb1250bcc06a5317756d16808ade6a5cb705366fead8c10d6781e19844"

  strings:
    $s1 = "DEAf]A`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}