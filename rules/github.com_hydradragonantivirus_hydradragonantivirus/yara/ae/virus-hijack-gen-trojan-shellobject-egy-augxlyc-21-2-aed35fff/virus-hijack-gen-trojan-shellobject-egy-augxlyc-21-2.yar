rule Virus_Hijack_Gen_Trojan_ShellObject_eGY_augxLYc_21_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.eGY@augxLYc_21_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9c02868816061a23054a0fbc8e7b4a1992570dc9a307b0701fb74cc38cf9e685"

  strings:
    $s1  = " **** Welcome to Contact Management System ****" fullword ascii
    $s2  = "email address:" fullword ascii
    $s3  = "[2] List all Contacts" fullword ascii
    $s4  = "[5] Delete a Contact" fullword ascii
    $s5  = "[4] Edit a Contact" fullword ascii
    $s6  = "[1] Add a new Contact" fullword ascii
    $s7  = "LIST OF CONTACTS" fullword ascii
    $s8  = "MAIN MENU" fullword ascii
    $s9  = "[3] Search for contact" fullword ascii
    $s10 = "Invalid choice" fullword ascii
    $s11 = "[1] Main Menu" fullword ascii
    $s12 = "To exit enter blank space in the name input" fullword ascii
    $s13 = "Enter the choice:" fullword ascii
    $s14 = "Phone No" fullword ascii
    $s15 = "..::Search result for '%s' " fullword ascii
    $s16 = "    Address" fullword ascii
    $s17 = "..::%d match(s) found!" fullword ascii
    $s18 = "..::email address:" fullword ascii
    $s19 = "..::Press any key to continue..." fullword ascii
    $s20 = "[0] Exit" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}