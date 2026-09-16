rule EPWIC_Sum_to_sqrt_2_lo_filter__flt32___32_lil_36_ {
  strings:
    $a0 = { 41 f6 e5 3c f8 9b 79 bd 95 48 96 bd 73 52 d4 3e b3 1d 4c 3f 73 52 d4 3e 95 48 96 bd f8 9b 79 bd 41 f6 e5 3c }

  condition:
    $a0
}