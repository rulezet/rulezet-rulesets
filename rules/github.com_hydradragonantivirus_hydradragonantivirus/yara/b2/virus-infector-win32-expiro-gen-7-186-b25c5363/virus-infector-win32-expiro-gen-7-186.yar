rule Virus_Infector_Win32_Expiro_Gen_7_186 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_186.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67d3f0969233e6c90e8418bde34aa53ac241211f28faa05bb1c7dd36879b7467"

  strings:
    $s1 = "-&hiGh" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}