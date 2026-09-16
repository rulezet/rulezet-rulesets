rule libavcodec_G729_cb_gain_2nd_8k__16_big_64_ {
  strings:
    $a0 = { 14 16 02 50 43 93 07 45 18 10 09 5b 3e f0 0d 40 03 3a 07 d5 4a 1d 17 2f 07 ca 00 00 3c 4a 00 ed 29 4d 0b 96 3b 1c 13 32 2d 31 04 ac 37 72 06 5e 1f 9b 12 fd 3b 39 37 c4 23 a0 02 0d 33 cc 0c b8 }

  condition:
    $a0
}