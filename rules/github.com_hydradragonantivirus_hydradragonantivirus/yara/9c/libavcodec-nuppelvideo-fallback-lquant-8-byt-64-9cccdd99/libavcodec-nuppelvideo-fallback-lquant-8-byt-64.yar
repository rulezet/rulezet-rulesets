rule libavcodec_nuppelvideo_fallback_lquant__8_byt_64_ {
  strings:
    $a0 = { 10 0b 0a 10 18 28 33 3d 0c 0c 0e 13 1a 3a 3c 37 0e 0d 10 18 28 39 45 38 0e 11 16 1d 33 57 50 3e 12 16 25 38 44 6d 67 4d 18 23 37 40 51 68 71 5c 31 40 4e 57 67 79 78 65 48 5c 5f 62 70 64 67 63 }

  condition:
    $a0
}