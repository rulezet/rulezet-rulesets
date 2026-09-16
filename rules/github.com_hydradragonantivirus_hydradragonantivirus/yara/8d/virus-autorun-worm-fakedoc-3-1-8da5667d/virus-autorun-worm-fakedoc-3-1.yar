rule Virus_Autorun_Worm_FakeDoc_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Worm.FakeDoc_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c3ad7d50c4271d63c30adc31aecb406279f4095df59e508490080ed98da5c19"

  strings:
    $s1 = "Event Viewer.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}