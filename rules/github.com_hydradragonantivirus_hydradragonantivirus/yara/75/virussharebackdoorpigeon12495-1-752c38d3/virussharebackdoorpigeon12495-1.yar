rule VirusShareBackDoorPigeon12495_1 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorPigeon12495_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1e38ffd98d308fef6dd71d34353d3c99b4450bbb0ce40874cb740f5a7805f26"

  strings:
    $s1 = "<Main>b__4_8" fullword ascii
    $s2 = "<Main>b__4_4" fullword ascii
    $s3 = "<Main>b__4_6" fullword ascii
    $s4 = "<Main>b__4_2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}