rule Trojan_Autorun_Dropped_Generic_Dacic_1A48D031_A_A0F7E65E {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.1A48D031.A.A0F7E65E.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "754a18bc16c030564b6e0a7e6baa7e44bc8144b2febb188772971ac0a5ef1838"

  strings:
    $s1 = "REFUSE" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}