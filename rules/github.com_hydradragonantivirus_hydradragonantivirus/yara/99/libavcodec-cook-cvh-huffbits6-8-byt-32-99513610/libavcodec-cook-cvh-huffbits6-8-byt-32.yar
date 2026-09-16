rule libavcodec_COOK_cvh_huffbits6__8_byt_32_ {
  strings:
    $a0 = { 01 04 04 06 04 06 06 08 04 06 06 08 06 09 08 0a 04 06 07 08 06 09 08 0b 06 09 08 0a 08 0a 09 0b }

  condition:
    $a0
}