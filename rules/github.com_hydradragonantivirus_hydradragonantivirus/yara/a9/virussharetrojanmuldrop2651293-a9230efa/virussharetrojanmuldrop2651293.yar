rule VirusShareTrojanMulDrop2651293 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDrop2651293.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e33e9eb18919091d45ac1daa734a60ad1662809646285a14737a8176750fff4c"

  strings:
    $s1 = "PatH=%TEMp%" fullword ascii
    $s2 = "(\"%COmsPec%        /C   echO" fullword ascii
    $s3 = "\"cMd      /c TYpE" fullword ascii
    $s4 = " xY6kr%rAndOM%>" fullword ascii
    $s5 = "&stART " fullword ascii
    $s6 = "ecHO  " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}