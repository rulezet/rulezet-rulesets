rule Trojan_Danger_Generic_Dacic_1A7FA519_A_44F50077_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.44F50077_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ab20d7264baed2fd222441ada9c6635958ae54bb81a4e5e7d9bffa87abca02d"

  strings:
    $s1 = "lremainder of Section B remaining in full force and effect." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}