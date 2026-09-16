rule libavcodec_AAN_ff_inv_aanscales__16_lil_128_ {
  strings:
    $a0 = { 00 10 89 0b 3f 0c 9b 0d 00 10 5d 14 90 1d fe 39 89 0b 51 08 d4 08 cf 09 89 0b af 0e 51 15 cf 29 3f 0c d4 08 5f 09 6a 0a 3f 0c 96 0f a1 16 63 2c 9b 0d cf 09 6a 0a 92 0b 9b 0d 51 11 24 19 51 31 00 10 89 0b 3f 0c 9b 0d 00 10 5d 14 90 1d fe 39 5d 14 af 0e 96 0f 51 11 5d 14 eb 19 a1 25 cf 49 90 1d 51 15 a1 16 24 19 90 1d a1 25 a1 36 28 6b fe 39 cf 29 63 2c 51 31 fe 39 cf 49 28 6b 31 d2 }

  condition:
    $a0
}