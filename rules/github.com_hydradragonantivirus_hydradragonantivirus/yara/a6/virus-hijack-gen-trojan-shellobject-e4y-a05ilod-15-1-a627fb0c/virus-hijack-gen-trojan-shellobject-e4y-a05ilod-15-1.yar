rule Virus_Hijack_Gen_Trojan_ShellObject_e4Y_a05ilOd_15_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4Y@a05ilOd_15_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d272a532343b5ed709496bb8ca39eda7438c2cb57d284a2715615f433772cc3"

  strings:
    $s1  = "basinet" fullword ascii
    $s2  = "ireless" fullword ascii
    $s3  = "Abundantly" fullword ascii
    $s4  = "Beauteous" fullword ascii
    $s5  = "Antihistaminic" fullword ascii
    $s6  = "specie eresia torto" fullword wide
    $s7  = "Ghiaia restai volute" fullword wide
    $s8  = "Pliant" fullword ascii
    $s9  = "Procapitalist" fullword ascii
    $s10 = "I'*jumbo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}