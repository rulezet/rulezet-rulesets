import "pe"
rule W32ChirB_infected_pe {
   meta:
      description = "pp.exe appended to an exe"
      author = "wit0k"
      reference = ""
      date = "2018-08-31"
      hash1 = "6ca9ff59325d13f1dd69855d88633814c685bcf0db44415888a3ceeeab731493"
   strings:
      $s1 = "<html><HEAD></HEAD><body bgColor=3D#ffffff><iframe src=3Dcid:THE-CID height=3D0 width=3D0></iframe></body></html>" fullword ascii
      $s2 = "<html><script language=\"JavaScript\">window.open(\"readme.eml\", null,\"resizable=no,top=6000,left=6000\")</script></html>" fullword ascii
      $s3 = /FROM: .{1,20}@yahoo\.com/ fullword ascii nocase
      $s4 = /Content-Type: audio\/x-wav; name=.{1,20}.exe/ fullword ascii nocase
      $s5 = "\\runouce.exe" fullword ascii
      $s6 = "Net Send * My god! Some one killed ChineseHacker-2 Monitor" fullword ascii
      $s7 = "readme.eml" fullword ascii
      $s8 = "Runonce" fullword ascii
      $s9 = "SUBJECT: %s is comming!" fullword ascii
      $s10 = /MAIL FROM: .{1,20}@btamail\.net.\cn/ fullword ascii
      $s11 = "Content-id: THE-CID" fullword ascii
      $s12 = "btamail.net.cn" fullword ascii
      $s13 = "ChineseHacker-2" ascii wide
      $b14 = { 60 E8 E6 19 00 00 8B 74 24 20 E8 08 00 00 00 61 } 
      $ds1 = "This program cannot be run in DOS mode"
   condition:
      ( uint16(0) == 0xe860 and
         ( 8 of them ) and  ( $b14 at pe.entry_point ) and $ds1
      ) or ( all of them )
}