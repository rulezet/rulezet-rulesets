rule libfaad2_f_huffman_sa__8_byt_28_ {
  strings:
    $a0 = { F1 01 02 03 F8 04 05 06 F2 F0 EF 07 08 09 F3 EE F4 0A 0B 0C F5 F6 ED EC F7 0D EA EB }

  condition:
    $a0
}