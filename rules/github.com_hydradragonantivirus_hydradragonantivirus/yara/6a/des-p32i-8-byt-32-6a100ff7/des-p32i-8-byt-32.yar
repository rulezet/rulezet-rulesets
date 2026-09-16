rule DES_p32i__8_byt_32_ {
  strings:
    $a0 = { 10 07 14 15 1d 0c 1c 11 01 0f 17 1a 05 12 1f 0a 02 08 18 0e 20 1b 03 09 13 0d 1e 06 16 0b 04 19 }

  condition:
    $a0
}