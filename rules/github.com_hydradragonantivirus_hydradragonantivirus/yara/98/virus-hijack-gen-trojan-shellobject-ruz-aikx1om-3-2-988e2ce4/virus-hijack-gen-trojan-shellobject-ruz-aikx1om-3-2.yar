rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aikx1Om_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aikx1Om_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29950ea67249b4774744481dfeda24370c2b7cfd574b00dbac7fd06414961760"

  strings:
    $s1  = "<description>FastStone Screen Cross Hair</description>" fullword ascii
    $s2  = "\"%1%\" already exists." fullword wide
    $s3  = "Reading mode" fullword wide
    $s4  = "FastStone Corporation" fullword wide
    $s5  = "Copyright (C) 2021 by FastStone Corporation" fullword wide
    $s6  = "Pause / Continue" fullword wide
    $s7  = "Grouped(" fullword ascii
    $s8  = "Filter(" fullword ascii
    $s9  = "Hint<uA" fullword ascii
    $s10 = "Height$8B" fullword ascii
    $s11 = "Screen Crosshair" fullword ascii
    $s12 = "Font,EB" fullword ascii
    $s13 = "Color 9B" fullword ascii
    $s14 = "Both lines" fullword wide
    $s15 = "Select \"Screen Crosshair\" again to close" fullword wide
    $s16 = "FastStone Screen Cross Hair" fullword wide
    $s17 = "!'%s' is not a valid integer value\"'%s' is not a valid currency value!'%g' is not a valid date and timeInvalid argument to tim" wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}