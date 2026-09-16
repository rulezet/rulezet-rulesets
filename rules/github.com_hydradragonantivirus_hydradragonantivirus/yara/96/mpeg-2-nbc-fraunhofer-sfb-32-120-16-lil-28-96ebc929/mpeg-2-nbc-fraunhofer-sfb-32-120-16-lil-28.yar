rule MPEG_2_NBC_Fraunhofer_sfb_32_120__16_lil_28_ {
  strings:
    $a0 = { 04 00 08 00 0c 00 10 00 14 00 1c 00 24 00 2c 00 38 00 44 00 50 00 60 00 70 00 78 00 }

  condition:
    $a0
}