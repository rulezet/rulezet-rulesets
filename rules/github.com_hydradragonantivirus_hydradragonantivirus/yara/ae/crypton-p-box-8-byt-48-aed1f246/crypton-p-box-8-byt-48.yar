rule Crypton_p_box__8_byt_48_ {
  strings:
    $a0 = { 0f 09 06 08 09 09 04 0c 06 02 06 0a 01 03 05 0f 0a 0f 04 07 05 02 0e 06 09 03 0c 08 0d 01 0b 00 00 04 08 04 02 0f 08 0d 01 01 0f 07 02 0b 0e 0f }

  condition:
    $a0
}