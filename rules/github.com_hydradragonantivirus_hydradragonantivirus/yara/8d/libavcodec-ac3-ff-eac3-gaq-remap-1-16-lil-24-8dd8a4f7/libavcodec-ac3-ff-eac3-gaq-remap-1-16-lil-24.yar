rule libavcodec_AC3_ff_eac3_gaq_remap_1__16_lil_24_ {
  strings:
    $a0 = { 49 12 89 08 21 04 08 02 02 01 81 00 40 00 20 00 10 00 08 00 02 00 00 00 }

  condition:
    $a0
}