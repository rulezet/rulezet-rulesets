rule scaled_down_product_of_jpeg_quantizer_and_AAN_premul_table__8_byt_64_ {
  strings:
    $a0 = { 10 0f 0d 13 18 1f 1c 11 11 17 19 1f 24 3f 2d 15 12 18 1b 25 34 3b 31 14 10 1c 22 28 3c 50 33 14 12 1f 30 42 44 56 38 15 13 26 38 3b 40 40 30 14 1b 30 37 37 38 33 23 0f 14 23 22 20 1f 16 0f 08 }

  condition:
    $a0
}