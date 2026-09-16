import "pe"
rule trickbot_kpsiwn {
  meta:
    description = "exe - file kpsiwn.exe"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-01-05"
    hash1       = "e410123bde6a317cadcaf1fa3502301b7aad6f528d59b6b60c97be077ef5da00"

  strings:
    $s1  = "C:\\Windows\\explorer.exe" fullword ascii
    $s2  = "constructor or from DllMain." fullword ascii
    $s3  = "esource" fullword ascii
    $s4  = "Snapping window demonstration" fullword wide
    $s5  = "EEEEEEEEEFFB" ascii
    $s6  = "EEEEEEEEEEFC" ascii
    $s7  = "EEEEEEEEEEFD" ascii
    $s8  = "DINGXXPADDINGPADDINGXXPADDINGPADDINGXXPAD" fullword ascii
    $s9  = "EFEEEEEEEEEB" ascii
    $s10 = "e[!0LoG" fullword ascii
    $s11 = ">*P<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\">" fullword ascii
    $s12 = "o};k- " fullword ascii
    $s13 = "YYh V+ i" fullword ascii
    $s14 = "fdlvic" fullword ascii
    $s15 = "%FD%={" fullword ascii
    $s16 = "QnzwM#`8" fullword ascii
    $s17 = "xfbS/&s:" fullword ascii
    $s18 = "1#jOSV9\"" fullword ascii
    $s19 = "JxYt1L=]" fullword ascii
    $s20 = "a3NdcMFSZEmJwXod1oyI@Tj4^mY+UsZqK3>fTg<P*$4DC?y@esDpRk@T%t" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and
    (pe.imphash() == "a885f66621e03089e6c6a82d44a5ebe3" or 10 of them)
}