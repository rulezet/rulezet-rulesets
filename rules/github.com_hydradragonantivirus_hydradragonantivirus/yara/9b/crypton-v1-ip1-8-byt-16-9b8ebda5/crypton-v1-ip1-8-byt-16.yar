rule Crypton_v1_ip1__8_byt_16_ {
  strings:
    $a0 = { 06 0c 0e 0a 0b 07 09 03 04 0d 01 00 0f 02 05 08 }

  condition:
    $a0
}