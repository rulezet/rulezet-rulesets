rule libavcodec_real_audio_288_gain_window__flt32___32_lil_152_ {
  strings:
    $a0 = { 8e 75 01 3f f9 31 06 3f 43 1c 0b 3f 6e 34 10 3f 00 7e 15 3f 00 f8 1a 3f 00 a4 20 3f 00 86 26 3f 00 a0 2c 3f 00 f2 32 3f 00 7e 39 3f 00 4a 40 3f 00 54 47 3f 00 a0 4e 3f 00 30 56 3f 00 08 5e 3f 00 2a 66 3f 00 98 6e 3f 00 24 76 3f 00 96 7b 3f 00 e2 7e 3f 00 00 80 3f 00 ee 7e 3f 00 b0 7b 3f 00 4a 76 3f 00 ca 6e 3f 00 40 65 3f 00 c0 59 3f 00 64 4c 3f 00 48 3d 3f 00 90 2c 3f 00 5e 1a 3f 00 da 06 3f 00 5c e4 3e 00 14 b9 3e 00 34 8c 3e 00 48 3c 3e 00 20 bd 3d }

  condition:
    $a0
}