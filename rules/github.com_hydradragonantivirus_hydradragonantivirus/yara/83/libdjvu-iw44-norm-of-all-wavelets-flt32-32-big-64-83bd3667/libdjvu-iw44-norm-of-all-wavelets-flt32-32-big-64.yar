rule libdjvu_IW44_norm_of_all_wavelets__flt32___32_big_64_ {
  strings:
    $a0 = { 45 24 3f d3 43 37 4a 10 43 37 4b c0 42 4c 96 6d 42 37 55 71 42 37 56 a7 41 4c ad 0e 41 37 f2 86 41 37 f4 34 40 4e 02 43 40 3f f4 38 40 3f f7 6a 3f 5f 91 a5 3f 89 87 9c 3f 89 89 94 3e db 9c f3 }

  condition:
    $a0
}