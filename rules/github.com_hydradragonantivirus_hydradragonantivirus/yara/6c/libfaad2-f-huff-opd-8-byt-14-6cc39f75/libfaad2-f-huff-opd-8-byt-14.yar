rule libfaad2_f_huff_opd__8_byt_14_ {
  strings:
    $a0 = { 01 E1 02 03 E8 E2 04 05 E4 E7 E3 06 E6 E5 }

  condition:
    $a0
}