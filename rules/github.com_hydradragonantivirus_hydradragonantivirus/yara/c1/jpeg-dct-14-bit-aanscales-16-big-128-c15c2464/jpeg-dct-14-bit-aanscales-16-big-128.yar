rule Jpeg_dct_14_bit_aanscales__16_big_128_ {
  strings:
    $a0 = { 40 00 58 c5 53 9f 4b 42 40 00 32 49 22 a3 11 a8 58 c5 7b 21 73 fc 68 62 58 c5 45 bf 30 0b 18 7e 53 9f 73 fc 6d 41 62 54 53 9f 41 b3 2d 41 17 12 4b 42 68 62 62 54 58 7e 4b 42 3b 21 28 ba 14 c3 40 00 58 c5 53 9f 4b 42 40 00 32 49 22 a3 11 a8 32 49 45 bf 41 b3 3b 21 32 49 27 82 1b 37 0d e0 22 a3 30 0b 2d 41 28 ba 22 a3 1b 37 12 bf 09 8e 11 a8 18 7e 17 12 14 c3 11 a8 0d e0 09 8e 04 df }

  condition:
    $a0
}