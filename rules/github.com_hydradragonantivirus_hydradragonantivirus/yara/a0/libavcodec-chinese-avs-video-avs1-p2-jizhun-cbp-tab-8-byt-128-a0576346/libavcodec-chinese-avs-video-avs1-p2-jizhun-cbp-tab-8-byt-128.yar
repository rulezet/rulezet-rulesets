rule libavcodec_Chinese_AVS_video__AVS1_P2__JiZhun__cbp_tab__8_byt_128_ {
  strings:
    $a0 = { 3f 00 0f 0f 1f 3f 2f 1f 00 10 0e 20 0d 2f 0b 0d 07 0e 05 0b 0a 0c 08 05 0c 0a 3d 07 04 30 37 03 01 02 02 08 3b 04 03 01 3e 3d 09 37 06 3b 1d 3e 2d 1d 33 1b 17 17 27 13 1b 1e 2e 1c 35 09 1e 06 2b 3c 25 15 3c 2c 10 1a 15 33 1c 23 13 12 23 14 2a 18 1a 35 2c 11 20 25 3a 27 18 2d 14 3a 11 2b 12 2a 30 2e 16 24 21 21 19 22 31 28 28 34 24 31 22 32 32 38 34 19 36 16 29 36 38 39 26 29 39 26 }

  condition:
    $a0
}