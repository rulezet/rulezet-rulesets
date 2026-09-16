rule Virus_Hijack_Gen_Trojan_ShellObject_RAZ_aCEmdoo_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.RAZ@aCEmdoo_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4ef2a259bd3dd7ec501ec8afa4deedca81cb12dda95f69c6b91f2f6f5079b56a"

  strings:
    $s1  = "<description>FastStone Screen Focus</description>" fullword ascii
    $s2  = "\"%1%\" already exists." fullword wide
    $s3  = "Ctrl && Shift : " fullword wide
    $s4  = "FastStone Corporation" fullword wide
    $s5  = "Ctrl && Shift : Select      Alt +/- : Size      Shift +/- : Dim      Esc : Close" fullword wide
    $s6  = "Ctrl && Shift : Select      Shift +/- : Dim      Esc : Close" fullword wide
    $s7  = "Strg && Umsch : Select      Alt +/- : " fullword wide
    $s8  = "Ctrl && Shift : Select      Alt +/- : " fullword wide
    $s9  = "Ctrl && Umsch : Select      Umsch +/- : " fullword wide
    $s10 = "Ctrl && Shift : Select      Shift +/- : " fullword wide
    $s11 = "Copyright (C) 2023 by FastStone Corporation" fullword wide
    $s12 = "Grouped(" fullword ascii
    $s13 = "Screen Focus" fullword ascii
    $s14 = "FastStone Screen Focus" fullword wide
    $s15 = "Filter(" fullword ascii
    $s16 = "TAction$" fullword ascii
    $s17 = "Glyph<NF" fullword ascii
    $s18 = "Size`8B" fullword ascii
    $s19 = "Align,tA" fullword ascii
    $s20 = "!'%s' is not a valid integer value\"'%s' is not a valid currency value!'%g' is not a valid date and timeInvalid argument to tim" wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}