rule Crypton_v1_p1__8_byt_16_ {
  strings:
    $a0 = { 0b 0a 0d 07 08 0e 00 05 0f 06 03 04 01 09 02 0c }

  condition:
    $a0
}