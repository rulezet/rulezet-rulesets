rule VirusShareBackDoorPigeon12495 {
  meta:
    description = "datamaliciousorder - file VirusShareBackDoorPigeon12495.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47e44e4ef3df45e51651c87a9e242c7876535aebdff074cb61d45d6e38741c97"

  strings:
    $s1  = "OLE error %.8x.Method '%s' not supported by automation object/Variant does not reference an automation object7Dispatch methods d" wide
    $s2  = "MENUBUTTON_HINT=System menu" fullword ascii
    $s3  = "NODISKINDRIVE=There is no disk in Drive or Drive is not ready" fullword ascii
    $s4  = "PRNDLG_WARNING=There are no printers in your system!" fullword ascii
    $s5  = "System menu" fullword wide
    $s6  = "graceful close" fullword ascii
    $s7  = "Add to Custom Colors" fullword wide
    $s8  = "FIND_WHAT=Find what:" fullword ascii
    $s9  = "MSG_BTN_ABORT=&Abort" fullword ascii
    $s10 = "MSG_BTN_VIEWMENU_HINT=View Menu" fullword ascii
    $s11 = "MSG_FILETYPE=File type:" fullword ascii
    $s12 = "FIND_REPLACE_WITH=Replace with:" fullword ascii
    $s13 = "TRAYBUTTON_HINT=Minimize to Tray" fullword ascii
    $s14 = "MSG_BTN_BACK_HINT=Go To Last Folder Visited" fullword ascii
    $s15 = "DB_DELETE_QUESTION=Delete record?" fullword ascii
    $s16 = "MSG_BTN_HELP=&Help" fullword ascii
    $s17 = "Intel Indeo(R) Video R3.2" fullword ascii
    $s18 = "PRNDLG_PRINTTOFILE=Print to file" fullword ascii
    $s19 = "NOVALIDDRIVEID=Not a valid Drive ID" fullword ascii
    $s20 = "MSG_BTN_NEWFOLDER_HINT=Create New Folder" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}