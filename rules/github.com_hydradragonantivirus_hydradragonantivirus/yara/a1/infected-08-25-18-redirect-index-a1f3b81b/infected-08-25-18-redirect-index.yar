rule infected_08_25_18_redirect_index {
  meta:
    description = "redirect - file index.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2018-08-25"
    hash1       = "3eb001a420107db7c78640d8d1f7c8984e19f39f4f03b09dbf7f42c79f19ae45"

  strings:
    $s1 = "<?php ${\"G\\x4c\\x4f\\x42ALS\"}[\"f\\x65\\x78\\x67\\x74\\x69\\x72\\x76\\x64\\x66\"]=\"\\x73r\\x63\";${\"\\x47\\x4c\\x4f\\x42\\x" ascii

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 20KB and
      (all of them)
    ) or (all of them)
}