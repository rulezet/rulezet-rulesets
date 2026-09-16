rule libavcodec_COOK_cvh_huffbits0__8_byt_191_ {
  strings:
    $a0 = { 01 04 06 06 07 07 08 08 08 09 09 0a 0b 0b 04 05 06 07 07 08 08 09 09 09 09 0a 0b 0b 05 06 07 08 08 09 09 09 09 0a 0a 0a 0b 0c 06 07 08 09 09 09 09 0a 0a 0a 0a 0b 0c 0d 07 07 08 09 09 09 0a 0a 0a 0a 0b 0b 0c 0d 08 08 09 09 09 0a 0a 0a 0a 0b 0b 0c 0d 0e 08 08 09 09 0a 0a 0b 0b 0b 0c 0c 0d 0d 0f 08 08 09 09 0a 0a 0b 0b 0b 0c 0c 0d 0e 0f 09 09 09 0a 0a 0a 0b 0b 0c 0d 0c 0e 0f 10 09 09 0a 0a 0a 0a 0b 0c 0c 0e 0e 10 10 00 09 09 0a 0a 0b 0b 0c 0d 0d 0e 0e 0f 00 00 0a 0a 0a 0b 0b 0c 0c 0d 0f 0f 10 00 00 00 0b 0b 0b 0c 0d 0d 0d 0f 10 10 00 00 00 00 0b 0b 0c 0d 0d 0e 0f 10 10 }

  condition:
    $a0
}