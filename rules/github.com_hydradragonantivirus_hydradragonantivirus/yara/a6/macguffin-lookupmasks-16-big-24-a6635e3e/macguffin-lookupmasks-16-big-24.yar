rule MacGuffin_lookupmasks__16_big_24_ {
  strings:
    $a0 = { 00 36 06 c0 69 00 50 48 21 06 84 11 86 01 48 28 10 c4 29 80 90 11 02 2a }

  condition:
    $a0
}