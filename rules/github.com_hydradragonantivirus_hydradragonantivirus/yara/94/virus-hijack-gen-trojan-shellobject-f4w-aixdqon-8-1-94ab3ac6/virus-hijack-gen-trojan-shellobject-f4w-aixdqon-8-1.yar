rule Virus_Hijack_Gen_Trojan_ShellObject_f4W_aixDqOn_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f4W@aixDqOn_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d24ea58e3a5a1320cbfff12deb10b74868f1587f7f623fd0503ccbc7930093a2"

  strings:
    $s1  = "The link is no longer a %s. Please choose a different command offered by the new type." fullword ascii
    $s2  = "Inserts the contents of the Clipboard into your document as %s.  Paste Link creates a link to the source file so that changes to" ascii
    $s3  = "Inserts the contents of the Clipboard into your document so that you may activate it using %s.  It will be displayed as an icon." ascii
    $s4  = "Operation failed!" fullword ascii
    $s5  = "+Inserts a new %s object into your document.MInserts a new %s object into your document.  It will be displayed as an icon.gInser" ascii
    $s6  = "Inserts the contents of the Clipboard into your document as %s.  Paste Link creates a link to the source file so that changes to" ascii
    $s7  = "?Inserts the contents of the Clipboard into your document as %s.^Inserts the contents of the Clipboard into your document so tha" ascii
    $s8  = "Could not open file!,Disk full--unable to complete save operation" fullword ascii
    $s9  = "?Inserts the contents of the Clipboard into your document as %s.^Inserts the contents of the Clipboard into your document so tha" ascii
    $s10 = "OleStdCreateTempFileMoniker: Moniker NOT released" fullword ascii
    $s11 = "ts the contents of the file as an object into your document so that you may activate it using the " fullword ascii
    $s12 = "Microsoft Windows(TM) OLE 2.0 User Interface Support" fullword ascii
    $s13 = "&Unable to open file %s. Access denied.*Unable to open file %s. Sharing violation.(Unable to open file %s. General failure." fullword ascii
    $s14 = "Inserts a picture of the Clipboard contents into your document.  Paste Link creates a link to the source file so that changes to" ascii
    $s15 = "Inserts an icon into your document which represents the Clipboard contents.  Paste Link creates a link to the source file so tha" ascii
    $s16 = "Inserts an icon into your document which represents the Clipboard contents.  Paste Link creates a link to the source file so tha" ascii
    $s17 = "Inserts a picture of the Clipboard contents into your document.  Paste Link creates a link to the source file so that changes to" ascii
    $s18 = "9Inserts the contents of the Clipboard into your document." fullword ascii
    $s19 = "Change Source+Invalid Source : Do you want to correct it?Fail to get source of the link!&Fail to get update option of the link!" ascii
    $s20 = "Fail to add item to ListBox!lThe selected link has been changed." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}