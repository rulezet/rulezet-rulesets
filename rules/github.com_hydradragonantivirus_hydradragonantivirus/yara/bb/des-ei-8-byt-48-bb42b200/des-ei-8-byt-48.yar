rule DES_ei__8_byt_48_ {
  strings:
    $a0 = { 20 01 02 03 04 05 04 05 06 07 08 09 08 09 0a 0b 0c 0d 0c 0d 0e 0f 10 11 10 11 12 13 14 15 14 15 16 17 18 19 18 19 1a 1b 1c 1d 1c 1d 1e 1f 20 01 }

  condition:
    $a0
}