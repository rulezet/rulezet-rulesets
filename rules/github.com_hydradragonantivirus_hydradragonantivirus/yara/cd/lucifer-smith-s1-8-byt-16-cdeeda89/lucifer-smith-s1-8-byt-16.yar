rule Lucifer__smith__s1__8_byt_16_ {
  strings:
    $a0 = { 07 02 0e 09 03 0b 00 04 0c 0d 01 0a 06 0f 08 05 }

  condition:
    $a0
}