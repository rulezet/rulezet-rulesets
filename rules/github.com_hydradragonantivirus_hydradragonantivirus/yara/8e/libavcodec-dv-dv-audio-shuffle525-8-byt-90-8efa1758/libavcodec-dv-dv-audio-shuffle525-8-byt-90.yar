rule libavcodec_DV_dv_audio_shuffle525__8_byt_90_ {
  strings:
    $a0 = { 00 1e 3c 14 32 50 0a 28 46 06 24 42 1a 38 56 10 2e 4c 0c 2a 48 02 20 3e 16 34 52 12 30 4e 08 26 44 1c 3a 58 18 36 54 0e 2c 4a 04 22 40 01 1f 3d 15 33 51 0b 29 47 07 25 43 1b 39 57 11 2f 4d 0d 2b 49 03 21 3f 17 35 53 13 31 4f 09 27 45 1d 3b 59 19 37 55 0f 2d 4b 05 23 41 }

  condition:
    $a0
}