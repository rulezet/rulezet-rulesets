rule _infected_06_07_18_prowli_botnet_IOC3_C2 {
  meta:
    description = "prowli - file IOC3-C2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-07"
    hash1       = "4b5066f743ec9fb32c85c579b12b87a10b9433a9988ce4439b07f82a553bfb6f"

  strings:
    $s1 = "ip2_log.txt" fullword ascii
    $s2 = "ip3_log.txt" fullword ascii
    $s3 = "mhcl_log.txt" fullword ascii
    $s4 = "dru_log.txt" fullword ascii
    $s5 = "ip4_log.txt" fullword ascii
    $s6 = "$myfile = file_put_contents( " fullword ascii
    $s7 = "elseif ( isset ($_GET[" fullword ascii
    $s8 = "if ( isset ($_GET[" fullword ascii
    $s9 = "if ( isset ($_GET[ " fullword ascii

  condition:
    (uint16(0) == 0x6669 and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}