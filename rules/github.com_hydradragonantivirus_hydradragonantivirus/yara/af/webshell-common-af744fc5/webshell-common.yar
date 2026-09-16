rule webshell_common {
  meta:
    description = "PHP - file webshell_common.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara/"
    date        = "2019-10-11"
    hash1       = "447ee26b5dfde1e5feda755894874a2b49742bec803a29e089badd9ebd45bfa1"

  strings:
    $s1 = "if ($_SERVER[\"QUERY_STRING\"]) { exit($_SERVER[\"QUERY_STRING\"]); }" fullword ascii
    $s2 = "<?php"
    $s3 = "goto"

  condition:
    (uint16(0) == 0x3f3c and
      filesize < 300KB and
      (all of them)
    ) or (all of them)
}