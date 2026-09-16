rule libavcodec_real_audio_288_gain_window__flt32___32_big_152_ {
  strings:
    $a0 = { 3f 01 75 8e 3f 06 31 f9 3f 0b 1c 43 3f 10 34 6e 3f 15 7e 00 3f 1a f8 00 3f 20 a4 00 3f 26 86 00 3f 2c a0 00 3f 32 f2 00 3f 39 7e 00 3f 40 4a 00 3f 47 54 00 3f 4e a0 00 3f 56 30 00 3f 5e 08 00 3f 66 2a 00 3f 6e 98 00 3f 76 24 00 3f 7b 96 00 3f 7e e2 00 3f 80 00 00 3f 7e ee 00 3f 7b b0 00 3f 76 4a 00 3f 6e ca 00 3f 65 40 00 3f 59 c0 00 3f 4c 64 00 3f 3d 48 00 3f 2c 90 00 3f 1a 5e 00 3f 06 da 00 3e e4 5c 00 3e b9 14 00 3e 8c 34 00 3e 3c 48 00 3d bd 20 00 }

  condition:
    $a0
}