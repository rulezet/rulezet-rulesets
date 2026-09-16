rule hyietnrfrx_7685 {
  meta:
    description = "Files - file hyietnrfrx.uit"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2022-02-01"
    hash1       = "70a49561f39bb362a2ef79db15e326812912c17d6e6eb38ef40343a95409a19a"

  strings:
    $s1  = "Z)* -^'" fullword ascii
    $s2  = "%EGMf%mzT" fullword ascii
    $s3  = "CYR:\"n" fullword ascii
    $s4  = "CbIN$P;" fullword ascii
    $s5  = "We:\\>K" fullword ascii
    $s6  = "h^nd* " fullword ascii
    $s7  = "+ GR;q" fullword ascii
    $s8  = "u%P%r2A" fullword ascii
    $s9  = "ti+ gj?" fullword ascii
    $s10 = "glMNdH8" fullword ascii
    $s11 = "SuiMFrn7" fullword ascii
    $s12 = "K* B5T" fullword ascii
    $s13 = "eLpsNt " fullword ascii
    $s14 = "aQeG% SMF " fullword ascii
    $s15 = "JdYQ67 " fullword ascii
    $s16 = "f>xYrBDvNF+Q" fullword ascii
    $s17 = "OESW[>O" fullword ascii
    $s18 = "9rlPY5__" fullword ascii
    $s19 = "DMvH{}L" fullword ascii
    $s20 = ".dgQ>H" fullword ascii

  condition:
    uint16(0) == 0x4eee and filesize < 2000KB and
    8 of them
}