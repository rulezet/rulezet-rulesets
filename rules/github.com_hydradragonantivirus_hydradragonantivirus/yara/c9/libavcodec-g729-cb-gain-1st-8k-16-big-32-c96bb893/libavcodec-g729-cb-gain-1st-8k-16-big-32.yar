rule libavcodec_G729_cb_gain_1st_8k__16_big_32_ {
  strings:
    $a0 = { 0c aa 26 dd 06 0f 09 79 0a 76 6a 1a 07 81 24 4b 07 27 13 9e 00 01 05 ec 01 64 39 a4 00 39 15 1c }

  condition:
    $a0
}