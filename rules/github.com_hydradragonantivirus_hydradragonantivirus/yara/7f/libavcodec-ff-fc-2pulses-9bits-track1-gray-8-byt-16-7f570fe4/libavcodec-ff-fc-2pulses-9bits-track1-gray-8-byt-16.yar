rule libavcodec_ff_fc_2pulses_9bits_track1_gray__8_byt_16_ {
  strings:
    $a0 = { 01 03 08 06 12 10 0b 0d 26 24 1f 21 15 17 1c 1a }

  condition:
    $a0
}