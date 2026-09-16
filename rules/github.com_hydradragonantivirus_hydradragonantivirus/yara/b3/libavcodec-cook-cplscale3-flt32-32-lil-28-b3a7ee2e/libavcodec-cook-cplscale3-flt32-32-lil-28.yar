rule libavcodec_COOK_cplscale3__flt32___32_lil_28_ {
  strings:
    $a0 = { 27 35 7b 3f 13 df 6f 3f 3e 3d 60 3f f3 04 35 3f 12 01 f7 3e 25 dc b2 3e a7 35 45 3e }

  condition:
    $a0
}