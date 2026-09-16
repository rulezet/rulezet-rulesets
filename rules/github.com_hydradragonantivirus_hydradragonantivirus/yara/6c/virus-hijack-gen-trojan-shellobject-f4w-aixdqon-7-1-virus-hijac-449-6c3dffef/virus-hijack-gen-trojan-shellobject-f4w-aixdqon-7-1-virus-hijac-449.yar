import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f4W_aixDqOn_7_1_Virus_Hijac_449 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_7_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@a45ajXp_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c39ed073ecc4cb372eedb12da81184d440c6eb2e2be1e3fc8b731ad43355717e"
    hash2       = "906c9e4e5ab33e9c806bf6d599c20c12a923b135167ae404a119876bfdae42ab"

  strings:
    $s1 = "  * Bios Release Date = 2020-06-03T00:00:00" fullword ascii
    $s2 = "  * Bios Release Date = 2020-05-12T00:00:00" fullword ascii
    $s3 = "AU setting next sqm report timeout to 2020-04-22 03:42:47" fullword ascii
    $s4 = "AU setting next sqm report timeout to 2020-06-04 08:04:25" fullword ascii
    $s5 = "AU setting next sqm report timeout to 2020-06-03 08:04:20" fullword ascii
    $s6 = "AU setting next sqm report timeout to 2020-04-21 03:42:47" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a9192bab5c7c795c7488b69a1853f9c2" and (all of them)
    ) or (all of them)
}