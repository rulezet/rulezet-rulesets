rule libmpeg2_default_intra_quantizer_matrix__8_byt_64_ {
  strings:
    $a0 = { 08 10 10 13 10 13 16 16 16 16 16 16 1a 18 1a 1b 1b 1b 1a 1a 1a 1a 1b 1b 1b 1d 1d 1d 22 22 22 1d 1d 1d 1b 1b 1d 1d 20 20 22 22 25 26 25 23 23 22 23 26 26 28 28 28 30 30 2e 2e 38 38 3a 45 45 53 }

  condition:
    $a0
}