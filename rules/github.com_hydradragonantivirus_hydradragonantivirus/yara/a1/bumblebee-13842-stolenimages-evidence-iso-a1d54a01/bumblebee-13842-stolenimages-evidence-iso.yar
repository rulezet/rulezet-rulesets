rule bumblebee_13842_StolenImages_Evidence_iso {
  meta:
    description = "BumbleBee - file StolenImages_Evidence.iso"
    author      = "The DFIR Report via yarGen Rule Generator"
    reference   = "https://thedfirreport.com/2022/11/14/bumblebee-zeros-in-on-meterpreter/"
    date        = "2022-11-13"
    hash1       = "4bb67453a441f48c75d41f7dc56f8d58549ae94e7aeab48a7ffec8b78039e5cc"

  strings:
    $x1  = "$..\\..\\..\\..\\Windows\\System32\\cmd.exe*/c start rundll32.exe mkl2n.dll,kXlNkCKgFC\"%systemroot%\\system32\\imageres.dll" fullword wide
    $x2  = "C:\\Windows\\System32\\cmd.exe" fullword ascii
    $x3  = "%windir%\\system32\\cmd.exe" fullword ascii
    $x4  = "Gcmd.exe" fullword wide
    $s5  = "pxjjqif723uf35.dll" fullword ascii
    $s6  = "tenant unanimously delighted sail databases princess bicyclelist progress accused urge your science certainty dalton databases h" ascii
    $s7  = "mkl2n.dll" fullword wide
    $s8  = "JEFKKDJJKHFJ" fullword ascii  
    $s9  = "KFFJJEJKJK" fullword ascii  
    $s10 = "JHJGKDFEG" fullword ascii  
    $s11 = "IDJIIDFHE" fullword ascii  
    $s12 = "JHJFIHJJI" fullword ascii  
    $s13 = "EKGJKKEFHKFFE" fullword ascii  
    $s14 = "FJGJFKGFF" fullword ascii  
    $s15 = "IFFKJGJFK" fullword ascii  
    $s16 = "FKFJDIHJF" fullword ascii  
    $s17 = "EKFJFdHFG" fullword ascii  
    $s18 = "HJFJJdEdEIDK" fullword ascii  
    $s19 = "KFJHKDJdIGF" fullword ascii  
    $s20 = "documents.lnk" fullword wide

  condition:
    uint16(0) == 0x0000 and filesize < 13000KB and
    1 of ($x*) and 4 of them
}