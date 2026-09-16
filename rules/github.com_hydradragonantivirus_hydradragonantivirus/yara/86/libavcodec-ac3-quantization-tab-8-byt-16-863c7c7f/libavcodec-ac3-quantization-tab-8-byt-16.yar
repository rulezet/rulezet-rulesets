rule libavcodec_AC3_quantization_tab__8_byt_16_ {
  strings:
    $a0 = { 00 03 05 07 0b 0f 05 06 07 08 09 0a 0b 0c 0e 10 }

  condition:
    $a0
}