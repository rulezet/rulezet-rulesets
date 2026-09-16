rule libfaad2_f_huff_icc__8_byt_28_ {
  strings:
    $a0 = { E1 01 E2 02 E0 03 E3 04 DF 05 E4 06 DE 07 E5 08 E6 09 DD 0A E7 0B DC 0C E8 0D DB DA }

  condition:
    $a0
}