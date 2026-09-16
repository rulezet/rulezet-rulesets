rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aeWgNZc_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aeWgNZc_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f12529b481b2a8f78fe1769871649c0758ccd95565ee83f3ceb8f9f73dbfd9bc"

  strings:
    $s1 = "bObO*@Uj<G" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}