rule libavcodec_DV_dv_audio_shuffle625__8_byt_108_ {
  strings:
    $a0 = { 00 24 48 1a 3e 62 10 34 58 06 2a 4e 20 44 68 16 3a 5e 0c 30 54 02 26 4a 1c 40 64 12 36 5a 08 2c 50 22 46 6a 18 3c 60 0e 32 56 04 28 4c 1e 42 66 14 38 5c 0a 2e 52 01 25 49 1b 3f 63 11 35 59 07 2b 4f 21 45 69 17 3b 5f 0d 31 55 03 27 4b 1d 41 65 13 37 5b 09 2d 51 23 47 6b 19 3d 61 0f 33 57 05 29 4d 1f 43 67 15 39 5d 0b 2f 53 }

  condition:
    $a0
}