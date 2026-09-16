rule huffyuv_left_rgb__8_byt_112_ {
  strings:
    $a0 = { 63 24 25 26 47 88 c9 0a 0d 0b 13 0c 16 0d 1c 0e 21 0f 09 2e 2f 0e 0f 0d 18 2c 2d 0c 15 0b 13 0a 0b 09 08 a8 47 26 25 24 43 22 43 25 46 47 a8 09 09 0a 0e 0b 16 0c 18 0d 1a 0e 2e 0d 11 0c 1b 0b 14 0a 0e 09 0a c8 67 46 25 24 23 22 23 44 25 26 47 88 e9 0a 0b 0b 12 0c 18 0d 1c 2e 2d 0e 3d 0d 16 0c 15 0b 13 0a 0b 09 08 a8 47 26 25 44 23 00 }

  condition:
    $a0
}