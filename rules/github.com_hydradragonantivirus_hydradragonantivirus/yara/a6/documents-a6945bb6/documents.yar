rule Documents {
  meta:
    description = "8099 - file Documents.lnk"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2021/12/13/diavol-ransomware/"
    date        = "2021-12-12"
    hash1       = "e87f9f378590b95de1b1ef2aaab84e1d00f210fd6aaf5025d815f33096c9d162"

  strings:
    $x1  = "SharedFiles.dll,BasicScore\"%systemroot%\\system32\\imageres.dll" fullword wide
    $x2  = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
    $s3  = "C:\\Users\\User\\Documents" fullword wide
    $s4  = " ..\\Windows\\System32\\rundll32.exe" fullword wide
    $s5  = "User (C:\\Users)" fullword wide
    $s6  = ",System32" fullword wide
    $s7  = "Documents" fullword wide  
    $s8  = "windev2106eval" fullword ascii
    $s9  = "%Windows" fullword wide  
    $s10 = "OwHUSx" fullword ascii
    $s11 = "System Folder" fullword wide  

  condition:
    uint16(0) == 0x004c and filesize < 3KB and
    1 of ($x*) and all of them
}