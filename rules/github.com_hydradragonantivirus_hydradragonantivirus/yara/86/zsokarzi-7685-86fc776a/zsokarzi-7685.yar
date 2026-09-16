rule zsokarzi_7685 {
  meta:
    description = "Files - file zsokarzi.xpq"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2022-02-01"
    hash1       = "cbfc135bff84d63c4a0ccb5102cfa17d8c9bf297079f3b2f1371dafcbefea77c"

  strings:
    $s1  = "}poSpY" fullword ascii
    $s2  = "[cmD>S" fullword ascii
    $s3  = "# {y|4" fullword ascii
    $s4  = "IX%k%5u" fullword ascii
    $s5  = "YKeial7" fullword ascii
    $s6  = "#%y% !" fullword ascii
    $s7  = "wOUV591" fullword ascii
    $s8  = "| VJHt}&Y" fullword ascii
    $s9  = "BEgs% 5" fullword ascii
    $s10 = "UKCy\\n" fullword ascii
    $s11 = "w;gOxQ?" fullword ascii
    $s12 = "'OHSf\"/x" fullword ascii
    $s13 = "=#qVNkOnj" fullword ascii
    $s14 = "{_OqzbVbN" fullword ascii
    $s15 = "QEQro\\4" fullword ascii
    $s16 = "ohFq\\P" fullword ascii
    $s17 = "34eYZVnp2" fullword ascii
    $s18 = "rxuqLDG" fullword ascii
    $s19 = "kUZI6J#" fullword ascii
    $s20 = "IEJl1}+" fullword ascii

  condition:
    uint16(0) == 0xc1d7 and filesize < 2000KB and
    8 of them
}