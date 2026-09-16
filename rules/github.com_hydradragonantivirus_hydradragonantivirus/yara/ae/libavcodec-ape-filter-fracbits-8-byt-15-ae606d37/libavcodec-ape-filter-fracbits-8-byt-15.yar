rule libavcodec_ape_filter_fracbits__8_byt_15_ {
  strings:
    $a0 = { 00 00 00 0b 00 00 0b 00 00 0a 0d 00 0b 0d 0f }

  condition:
    $a0
}