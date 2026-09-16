rule libavcodec_AC3_ff_eac3_bits_vs_hebap__8_byt_20_ {
  strings:
    $a0 = { 00 02 03 04 05 07 08 09 03 04 05 06 07 08 09 0a 0b 0c 0e 10 }

  condition:
    $a0
}