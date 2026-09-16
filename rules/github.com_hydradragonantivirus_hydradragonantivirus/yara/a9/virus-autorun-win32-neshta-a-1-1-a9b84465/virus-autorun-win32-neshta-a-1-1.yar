rule Virus_Autorun_Win32_Neshta_A_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e76929673796923677b5dc9e65a0519b0b04897d699eb868ed1dd104c53c2338"

  strings:
    $s1 = "TRap?<RRRRn" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}