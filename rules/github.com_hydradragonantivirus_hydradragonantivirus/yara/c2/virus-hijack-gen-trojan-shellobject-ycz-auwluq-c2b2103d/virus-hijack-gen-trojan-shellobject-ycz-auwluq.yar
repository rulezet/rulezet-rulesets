rule Virus_Hijack_Gen_Trojan_ShellObject_YCZ_auWluQ {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.YCZ@auWluQ.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99997faf5e065f5e724a8dc670226a0afcf1b19afbb48b6309b2d5202e131b1f"

  strings:
    $s1 = "that you may receive from Microsoft during that year are also covered, but only for`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}