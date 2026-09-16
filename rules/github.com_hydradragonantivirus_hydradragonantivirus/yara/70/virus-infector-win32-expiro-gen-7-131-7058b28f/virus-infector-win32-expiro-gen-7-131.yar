rule Virus_Infector_Win32_Expiro_Gen_7_131 {
  meta:
    description = "datamaliciousorder - file Virus.Infector_Win32.Expiro.Gen.7_131.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "817a35b73c70af06eb70047416c5099b94d49c07e1a192d38c781a0f8cfdec1b"

  strings:
    $s1 = "ALOp>v8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}