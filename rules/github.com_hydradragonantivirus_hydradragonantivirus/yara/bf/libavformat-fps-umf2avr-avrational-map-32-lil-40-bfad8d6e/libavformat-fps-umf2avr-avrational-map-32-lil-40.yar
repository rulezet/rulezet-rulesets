rule libavformat_fps_umf2avr_AVRational_map__32_lil_40_ {
  strings:
    $a0 = { 32 00 00 00 01 00 00 00 60 ea 00 00 e9 03 00 00 18 00 00 00 01 00 00 00 19 00 00 00 01 00 00 00 30 75 00 00 e9 03 00 00 }

  condition:
    $a0
}