rule libmpdemux_vivo_h263_format__16_lil_28_ {
  strings:
    $a0 = { 00 00 00 00 80 00 60 00 b0 00 90 00 60 01 20 01 c0 02 40 02 80 05 80 04 40 01 f0 00 }

  condition:
    $a0
}