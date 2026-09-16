rule Virus_Hijack_Gen_Trojan_ShellObject_eSW_amMcCQb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eSW@amMcCQb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4f4de3f194acb135d2419c8ec3bbca2a15cbeaecdfb54471dc21f34a0ed530f"

  strings:
    $s1  = "Returns/sets the view style of header-cells or weekday-names." fullword ascii
    $s2  = "Returns/sets the background color used to display headers-cells." fullword ascii
    $s3  = "Returns/sets the foreground color used to display selected header-cells." fullword ascii
    $s4  = "Returns/sets the number of character used in the header-cells  (1-3)." fullword ascii
    $s5  = "Returns/sets the foreground color used to display header-cells." fullword ascii
    $s6  = "# day before,# day after,# days before,# days after,the" fullword wide
    $s7  = "# dia antes,# dia despu" fullword wide
    $s8  = "Returns/sets whether or not an object is painted at run time with 3-D effects." fullword ascii
    $s9  = "Hemisphere" fullword wide
    $s10 = "Returns/sets the view style of selected days-cells." fullword ascii
    $s11 = "Returns/sets the viewing the parts of other months." fullword ascii
    $s12 = "Returns/sets the foreground color of the thursday-cells." fullword ascii
    $s13 = "Returns/sets the foreground color used to display other month-cells." fullword ascii
    $s14 = "Returns/sets the background color used to display other month-cells." fullword ascii
    $s15 = "Returns/sets the foreground color used to display day of year-cell." fullword ascii
    $s16 = "Returns/sets the foreground color of the monday-cells." fullword ascii
    $s17 = "Returns/sets the foreground color of the saturday-cells." fullword ascii
    $s18 = "Returns/sets the background color used to display day-cells." fullword ascii
    $s19 = "Returns/sets the foreground color used to display selected-cells." fullword ascii
    $s20 = "Returns/sets the view style of day of year-cell." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}