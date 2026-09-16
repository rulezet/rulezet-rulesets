rule EPWIC_Sum_to_1_hi_filter__flt32___32_big_36_ {
  strings:
    $a0 = { 3c a2 9b 8e 3d 30 80 1a bd 54 88 72 be 96 22 66 3f 10 54 f2 be 96 22 66 bd 54 88 72 3d 30 80 1a 3c a2 9b 8e }

  condition:
    $a0
}