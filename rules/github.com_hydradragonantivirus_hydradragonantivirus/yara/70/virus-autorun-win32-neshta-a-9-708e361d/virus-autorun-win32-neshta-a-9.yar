rule Virus_Autorun_Win32_Neshta_A_9 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_9.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "102780c4455b0bb151b71eebf85a319b2260038449e42bc57af197a608f5d687"

  strings:
    $s1 = "able>::I" fullword ascii
    $s2 = "Client&" fullword ascii
    $s3 = "ityInteg@ration" fullword ascii
    $s4 = "WorkeBrC{Pool" fullword ascii
    $s5 = "Exit(ing'MM$M" fullword ascii
    $s6 = "Net::Dis patch" fullword ascii
    $s7 = "class II" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}