rule libavcodec_ultimotion_ulti_lumas__8_byt_64_ {
  strings:
    $a0 = { 10 13 17 1a 1e 21 25 28 2c 2f 33 36 3a 3d 41 44 48 4b 4f 52 56 59 5c 60 63 67 6a 6e 71 75 78 7c 7f 83 86 8a 8d 91 94 98 9b 9f a2 a5 a9 ac b0 b3 b7 ba be c1 c5 c8 cc cf d3 d6 da dd e1 e4 e8 eb }

  condition:
    $a0
}