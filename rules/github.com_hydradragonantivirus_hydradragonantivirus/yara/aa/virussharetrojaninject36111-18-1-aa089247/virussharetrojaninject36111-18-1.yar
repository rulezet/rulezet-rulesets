rule VirusShareTrojanInject36111_18_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanInject36111_18_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf7583a1c87be5e2e26481bb54763264f1e72dbf7e696d149d7703ac18ca3121"

  strings:
    $s1 = "FuckTheSystem Copyright " fullword wide
    $s2 = "9%nOeL" fullword ascii
    $s3 = "M\"AcrE" fullword ascii
    $s4 = "44 CALIBER" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}