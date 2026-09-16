rule _infected_06_07_18_prowli_botnet_IOC1 {
  meta:
    description = "prowli - file IOC1.js"
    author      = "Brian Laskowski"
    reference   = "https://github.com/Hestat/lw-yara"
    date        = "2018-06-07"
    hash1       = "0050aeefafcf679f9b9a925341d4ed61a9eb5c3e3fc17b653af730d543b6b080"

  strings:
    $s1 = "104, 116, 116, 112, 115, 58, 47, 47, 115, 116, 97, 116, 115, 46, 115, 116, 97, 114, 116, 114, 101, 99, 101, 105, 118, 101, 46, " fullword ascii
    $s2 = ", 46, 104, 101, 97, 100, 46, 97, 112, 112, 101, 110, 100, 67, 104, 105, 108, 100, 40, 122, 41, 59));" fullword ascii
    $s3 = "eval(String.fromCharCode" fullword ascii

  condition:
    (uint16(0) == 0x7665 and
      filesize < 2KB and
      (all of them)
    ) or (all of them)
}