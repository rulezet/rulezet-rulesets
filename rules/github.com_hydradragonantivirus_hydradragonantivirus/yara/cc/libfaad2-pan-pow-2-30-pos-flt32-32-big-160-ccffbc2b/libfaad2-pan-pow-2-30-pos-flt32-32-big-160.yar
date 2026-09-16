rule libfaad2_pan_pow_2_30_pos__flt32___32_big_160_ {
  strings:
    $a0 = { 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 00 00 3f 80 7d ff 3f 80 7d ff 3f 80 fc 7a 3f 80 fc 7a 3f 80 fc 7a 3f 80 fc 7a 3f 80 fc 7a 3f 81 fa e6 3f 82 7a d8 3f 82 7a d8 3f 81 7b 72 3f 81 fa e6 3f 82 fb 48 3f 84 7f 90 3f 85 01 fd 3f 81 fa e6 3f 82 fb 48 3f 84 7f 90 3f 86 8c 47 3f 87 95 97 3f 82 7a d8 3f 83 fd a4 3f 86 8c 47 3f 89 27 84 3f 8a be 19 3f 82 fb 48 3f 85 84 ea 3f 88 a1 07 3f 8b cf c3 3f 8e 85 31 3f 83 fd a4 3f 87 10 a3 3f 8a be 19 3f 8e 85 31 3f 92 66 9d }

  condition:
    $a0
}