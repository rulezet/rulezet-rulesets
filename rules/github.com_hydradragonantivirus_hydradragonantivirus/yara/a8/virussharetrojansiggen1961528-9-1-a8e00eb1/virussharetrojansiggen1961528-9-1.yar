rule VirusShareTrojanSiggen1961528_9_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1961528_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f18ad31e8a9dfaf58249bf9e41c202c4331938c12103f2915922db3f4c6f22e3"

  strings:
    $s1 = "your ps is start in the lamer system for all user" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}