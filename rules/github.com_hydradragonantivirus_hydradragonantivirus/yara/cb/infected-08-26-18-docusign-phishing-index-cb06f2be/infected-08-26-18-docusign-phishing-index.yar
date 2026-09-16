rule infected_08_26_18_DocuSign_phishing_index {
  meta:
    description = "phishing - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-26"
    hash1       = "9bb8e5f5e457524283ed2fccd54063a2f645e2209f4beeacc0304ec46a5032f0"

  strings:
    $s1 = "<meta http-equiv=\"content-type\" content=\"text/html; charset=windows-1252\"></head><body hola-ext-player=\"1\"><p>" fullword ascii
    $s2 = "<html hola_ext_inject=\"ready\"><head>" fullword ascii
    $s4 = "<p align=\"center\"><img src=\"img/bar.gif\" height=\"36\" width=\"405\"></p>" fullword ascii
    $s6 = "<img src=\"img/hl.jpg\" height=\"92\" width=\"405\"></p>" fullword ascii

  condition:
    (uint16(0) == 0x683c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}