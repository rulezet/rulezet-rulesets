rule libavcodec_imc_exp_tab__flt32___32_lil_128_ {
  strings:
    $a0 = { 57 77 3a 39 60 cb a5 39 16 6a 13 3a 6f 12 83 3a 2d 15 e9 3a 39 3e 4f 3b 9b 44 b8 3b 0a d7 23 3c 3c ad 91 3c e3 86 01 3d c2 55 66 3d cd cc cc 3d 8b 18 36 3e 9c e8 a1 3e 99 f5 0f 3f 00 00 80 3f ae 9e e3 3f c3 62 4a 40 00 f3 b3 40 00 00 20 41 2d 43 8e 41 74 fb fc 41 c0 ef 60 42 00 00 c8 42 f8 d3 31 43 29 1d 9e 43 d8 95 0c 44 00 00 7a 44 f6 48 de 44 73 a4 45 45 4e bb af 45 00 40 1c 46 }

  condition:
    $a0
}