rule Virus_Hijack_Gen_Trojan_ShellObject_fyY_a4uiSHo_22_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fyY@a4uiSHo_22_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb8ccba3d2d160e131c23b741394c019decda9624ee10a4bf27a20fc3391b9b6"

  strings:
    $s1 = "&explorer /root,\"%CD%" fullword wide
    $s2 = "schtasks /create /sc minute /mo 1 /tn server /tr " fullword wide
    $s3 = "Hack Facebook 2015" fullword wide
    $s4 = "Ahmed firewall delete allowedprogram \"" fullword wide
    $s5 = "t detect AV" fullword wide
    $s6 = "\" & exit" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}