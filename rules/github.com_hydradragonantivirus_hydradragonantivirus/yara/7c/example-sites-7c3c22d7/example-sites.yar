rule example_sites {
  meta:
    description = "05-26-18 - file example.sites.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-05-29"
    hash1       = "d69fbb7f46d2f2e17f239bf5df2cf0b5cf41759819100cbb4075d5870aa4dec7"

  strings:
    $s1 = "qHJgA=\";$YjzQVQ=\"tWlbh\";$xWjo=$YjzQVQ(\"8wj3cov0SvGOCvaI9AsJBgA=\");$jKB=$xWjo('',$YjzQVQ($Ymc));$jKB();}" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}