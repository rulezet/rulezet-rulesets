rule libavcodec_COOK_cplscale4__flt32___32_lil_60_ {
  strings:
    $a0 = { 13 d2 7d 3f d9 26 79 3f 29 f9 73 3f 3b 1d 6e 3f b6 48 67 3f 39 e9 5e 3f 90 80 53 3f f3 04 35 3f 59 3b 10 3f 65 c4 fb 3e d0 7c db 3e 74 04 bc 3e 6c 16 9b 3e 58 44 6b 3e 38 55 05 3e }

  condition:
    $a0
}