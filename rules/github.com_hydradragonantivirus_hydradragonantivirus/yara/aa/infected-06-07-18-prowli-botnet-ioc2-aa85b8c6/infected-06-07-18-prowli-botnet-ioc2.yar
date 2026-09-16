rule _infected_06_07_18_prowli_botnet_IOC2 {
  meta:
    description = "prowli - file IOC2.php"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-07"
    hash1       = "39dbf136e4191edaae8bb30aa0085ebd7e998d3b89cfb623a5a7e49f573c71ea"

  strings:
    $s1 = "99, 117, 109, 101, 110, 116, 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40, 122, 41, 59));" fullword ascii
  
  condition:
    (uint16(0) == 0x733c and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}