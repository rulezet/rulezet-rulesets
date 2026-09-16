import "pe"
rule bazar_M1E1626 {
  meta:
    description = "files - file M1E1626.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-01-25"
    hash1       = "d362c83e5a6701f9ae70c16063d743ea9fe6983d0c2b9aa2c2accf2d8ba5cb38"

  strings:
    $s1  = "ResizeFormToFit.EXE" fullword wide
    $s2  = "C:\\Windows\\explorer.exe" fullword ascii
    $s3  = "bhart@pinpub.com" fullword wide
    $s4  = "constructor or from DllMain." fullword ascii
    $s5  = "dgsvhwe" fullword ascii
    $s6  = "ResizeFormToFit.Document" fullword wide
    $s7  = "ResizeFormToFit Version 1.0" fullword wide
    $s8  = "This is a dummy form view for illustration of how to size the child frame window of the form to fit this form." fullword wide
    $s9  = "GSTEAQR" fullword ascii
    $s10 = "HTBNMRRTNSHNH" fullword ascii
    $s11 = "RCWZCSJXRRNBL" fullword ascii
    $s12 = "JFCNZXHXPTCT" fullword ascii
    $s13 = "BLNEJPFAWFPU" fullword ascii
    $s14 = "BREUORYYPKS" fullword ascii
    $s15 = "UCWOJTPGLBZTI" fullword ascii
    $s16 = "DZVVFAVZVWMVS" fullword ascii
    $s17 = "MNKRAMLGWUX" fullword ascii
    $s18 = "WHVMUKGVCHCT" fullword ascii
    $s19 = "\\W\\TQPNIQWNZN" fullword ascii
    $s20 = "ResizeFormToFit3" fullword wide

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "578738b5c4621e1bf95fce0a570a7cfc" or 8 of them)
}