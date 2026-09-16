rule Jpeg_dct_AA_N_scale_factor__flt32___32_lil_32_ {
  strings:
    $a0 = { 00 00 80 3f 86 8a b1 3f 75 3d a7 3f 17 83 96 3f 00 00 80 3f 4e 23 49 3f d4 8b 0a 3f af 42 8d 3e }

  condition:
    $a0
}