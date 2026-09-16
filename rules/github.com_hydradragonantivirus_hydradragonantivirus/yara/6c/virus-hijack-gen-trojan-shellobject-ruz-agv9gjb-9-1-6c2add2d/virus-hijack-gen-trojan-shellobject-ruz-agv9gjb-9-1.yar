rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d945423134f72c190ac5cf12a076bb345850b44f41e47c632acfe53b56f6750a"

  strings:
    $s1 = "7[MeSH" fullword ascii
    $s2 = "/[QUaG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}