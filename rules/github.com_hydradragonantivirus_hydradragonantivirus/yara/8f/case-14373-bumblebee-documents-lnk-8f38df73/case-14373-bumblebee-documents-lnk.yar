rule case_14373_bumblebee_documents_lnk {
  meta:
    description = "Files - file documents.lnk"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2022/09/26/bumblebee-round-two/"
    date        = "2022-09-26"
    hash1       = "cadd3f05b496ef137566c90c8fee3905ff13e8bda086b2f0d3cf7512092b541c"

  strings:
    $x1 = "tamirlan.dll,EdHVntqdWt\"%systemroot%\\system32\\imageres.dll" fullword wide
    $s2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
    $s3 = ")..\\..\\..\\..\\Windows\\System32\\rundll32.exe" fullword wide
    $s4 = "4System32" fullword wide
    $s5 = "user-pc" fullword ascii
    $s6 = "}Windows" fullword wide

  condition:
    uint16(0) == 0x004c and filesize < 4KB and
    1 of ($x*) and all of them
}