rule Virus_Hijack_Gen_Trojan_ShellObject_DyZ_a0Pysxf_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DyZ@a0Pysxf_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e81255ff6e0ed937603748c1442ce9d6588decf6922537037cf3f1a7369a8876"

  strings:
    $s1  = "<BODY ID=CV20_LoaderDlg BGCOLOR=LIGHTGREY style=\"font-family:MS Shell Dlg;font-size:8\">" fullword ascii
    $s2  = "V2.0_Loader, Version 1.0" fullword wide
    $s3  = "About V2.0_Loader" fullword wide
    $s4  = "start get all pass!" fullword ascii
    $s5  = "start get all pass 1!" fullword ascii
    $s6  = "get all pass!" fullword ascii
    $s7  = "download2 finished!" fullword ascii
    $s8  = "download1 finished!" fullword ascii
    $s9  = "&About V2.0_Loader..." fullword wide
    $s10 = "click ok!" fullword ascii
    $s11 = "<TABLE WIDTH=100% HEIGHT=100%>" fullword ascii
    $s12 = "<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonHelp\">Help</BUTTON>&nbsp;&nbsp;<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonOK\">OK</BUTTON>&n" ascii
    $s13 = "close window!" fullword ascii
    $s14 = "Internet Explorer 9" fullword wide
    $s15 = "Sleep:" fullword ascii
    $s16 = "q`hAko" fullword ascii
    $s17 = "TON STYLE=\"WIDTH:100\" ID=\"ButtonCancel\">Cancel</BUTTON>" fullword ascii
    $s18 = "<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonHelp\">Help</BUTTON>&nbsp;&nbsp;<BUTTON STYLE=\"WIDTH:100\" ID=\"ButtonOK\">OK</BUTTON>&n" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}