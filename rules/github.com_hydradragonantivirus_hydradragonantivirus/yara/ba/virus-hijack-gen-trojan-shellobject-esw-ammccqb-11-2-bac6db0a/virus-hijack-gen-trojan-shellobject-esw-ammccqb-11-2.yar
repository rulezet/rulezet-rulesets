rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_11_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_11_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4de586b66b962ee4d8d2dbbcd7b439017d69e08c3531e55105bf9a55773b75f"

  strings:
    $s1 = "All Picture Files|*.bmp;*.dib;*.gif;*.jpg;*.wmf;*.emf;*.ico;*.cur |" fullword wide
    $s2 = "Loading Error" fullword wide
    $s3 = "Performance Counter not available" fullword wide
    $s4 = "Show Render Time" fullword ascii
    $s5 = "Visual &Style" fullword ascii
    $s6 = "3D Studio Pro 5" fullword ascii
    $s7 = "3D Studio File|*.3ds" fullword wide
    $s8 = "Do you want to replace it." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}