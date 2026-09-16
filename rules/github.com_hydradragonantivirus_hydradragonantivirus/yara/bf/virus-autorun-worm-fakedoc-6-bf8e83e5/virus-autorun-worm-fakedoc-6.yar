rule Virus_Autorun_Worm_FakeDoc_6 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e71534d1b1aa5d7c39e2028578badf680d0e6f332ac9151ab87075bcb818111e"

  strings:
    $s1 = " Microsoft Office Word 97-2003" fullword ascii
    $s2 = "Font Style13" fullword wide
    $s3 = "Font Style14" fullword wide
    $s4 = "Body Text 21" fullword wide
    $s5 = "PAGE  " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}