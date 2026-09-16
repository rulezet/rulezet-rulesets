import "pe"
rule bazar_files_netscan {
  meta:
    description = "files - file netscan.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-01-25"
    hash1       = "ce6fc6cca035914a28bbc453ee3e8ef2b16a79afc01d8cb079c70c7aee0e693f"

  strings:
    $s1  = "TREMOTECOMMONFORM" fullword wide
    $s2  = "ELHEADERRIGHTBMP" fullword wide
    $s3  = "ELHEADERDESCBMP" fullword wide
    $s4  = "ELHEADERLEFTBMP" fullword wide
    $s5  = "ELHEADERASCBMP" fullword wide
    $s6  = "ELHEADERPOINTBMP" fullword wide
    $s7  = "<description>A free multithreaded IP, SNMP, NetBIOS scanner.</description>" fullword ascii
    $s8  = "GGG`BBB" fullword ascii  
    $s9  = "name=\"SoftPerfect Network Scanner\"/>" fullword ascii
    $s10 = "SoftPerfect Network Scanner" fullword wide
    $s11 = "TREMOTESERVICEEDITFORM" fullword wide
    $s12 = "TUSERPROMPTFORM" fullword wide
    $s13 = "TREMOTEWMIFORM" fullword wide
    $s14 = "TPUBLICIPFORM" fullword wide
    $s15 = "TREMOTESERVICESFORM" fullword wide
    $s16 = "TREMOTEWMIEDITFORM" fullword wide
    $s17 = "TREMOTEFILEEDITFORM" fullword wide
    $s18 = "TREMOTEREGISTRYFORM" fullword wide
    $s19 = "TPASTEIPADDRESSFORM" fullword wide
    $s20 = "TREMOTEREGISTRYEDITFORM" fullword wide

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "e9d20acdeaa8947f562cf14d3976522e" or 8 of them)
}