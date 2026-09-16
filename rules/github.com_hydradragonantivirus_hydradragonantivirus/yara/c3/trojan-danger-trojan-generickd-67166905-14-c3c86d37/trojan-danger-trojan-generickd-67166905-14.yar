rule Trojan_Danger_Trojan_GenericKD_67166905_14 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_14.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bfd8bcd757f8a3cfa52000a8fc0e9f4ce79615b6291f7ae90daff98d864bf4a"

  strings:
    $s1 = "x:44v[4Immersive Control Panel.lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}