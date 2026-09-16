rule libavcodec_AC3_ff_eac3_gaq_remap_2_4_a__16_lil_36_ {
  strings:
    $a0 = { 55 D5 B7 ED 25 C9 66 E6 44 C4 19 E3 11 C2 86 E1 04 C1 C2 E0 81 C0 60 E0 40 C0 30 E0 20 C0 18 E0 10 C0 0C E0 }

  condition:
    $a0
}