rule libfaad2_t_huffman_sa__8_byt_28_ {
  strings:
    $a0 = { F1 01 02 03 F0 F2 04 05 EF F3 06 07 EE F4 08 09 ED F5 0A 0B EC F6 EB 0C EA 0D F7 F8 }

  condition:
    $a0
}