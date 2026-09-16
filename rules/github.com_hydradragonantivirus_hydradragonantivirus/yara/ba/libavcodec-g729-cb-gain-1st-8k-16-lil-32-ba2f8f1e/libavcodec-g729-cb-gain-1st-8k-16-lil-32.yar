rule libavcodec_G729_cb_gain_1st_8k__16_lil_32_ {
  strings:
    $a0 = { aa 0c dd 26 0f 06 79 09 76 0a 1a 6a 81 07 4b 24 27 07 9e 13 01 00 ec 05 64 01 a4 39 39 00 1c 15 }

  condition:
    $a0
}