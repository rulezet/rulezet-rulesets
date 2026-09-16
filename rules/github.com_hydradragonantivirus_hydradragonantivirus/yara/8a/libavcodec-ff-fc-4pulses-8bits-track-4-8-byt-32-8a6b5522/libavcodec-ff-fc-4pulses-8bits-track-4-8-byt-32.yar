rule libavcodec_ff_fc_4pulses_8bits_track_4__8_byt_32_ {
  strings:
    $a0 = { 03 04 08 09 0d 0e 12 13 17 18 1c 1d 21 22 26 27 2b 2c 30 31 35 36 3a 3b 3f 40 44 45 49 4a 4e 4f }

  condition:
    $a0
}