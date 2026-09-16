rule Trojan_Danger_Trojan_Generic_36486627_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.36486627_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "232be79e0c13457f079df2eaf0097873d07634f98106b001f355d3ae625ef763"

  strings:
    $s1 = "VWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}