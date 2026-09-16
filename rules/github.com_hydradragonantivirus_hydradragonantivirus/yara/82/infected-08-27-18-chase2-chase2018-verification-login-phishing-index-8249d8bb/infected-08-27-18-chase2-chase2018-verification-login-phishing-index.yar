rule infected_08_27_18_chase2_chase2018_Verification_login_phishing_index {
  meta:
    description = "phishing - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-27"
    hash1       = "62c8059da62caafe0b90c10b71b9a97fbeed5b929a590d14c51945731fd8c735"

  strings:
    $s1 = "require \"includes/visitor_log.php\";" fullword ascii
    $s2 = "Created by legzy -- icq 692561824" fullword ascii
    $s3 = "require \"includes/blacklist_lookup.php\";" fullword ascii
    $s4 = "require \"includes/netcraft_check.php\";" fullword ascii
    $s5 = "require \"includes/ip_range_check.php\";" fullword ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 1KB and
      (all of them)
    ) or (all of them)
}