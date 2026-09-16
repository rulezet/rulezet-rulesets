rule Virus_Danger_Gen_Trojan_ShellObject_f0W_a0DbbBi {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.f0W@a0DbbBi.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ade93fa14b873a022f670cb7433aba815633daef06831d094fc6df3b2b103540"

  strings:
    $s1 = "&dispute under this agreement to which Section B applies must be filed within one year in small claims" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}