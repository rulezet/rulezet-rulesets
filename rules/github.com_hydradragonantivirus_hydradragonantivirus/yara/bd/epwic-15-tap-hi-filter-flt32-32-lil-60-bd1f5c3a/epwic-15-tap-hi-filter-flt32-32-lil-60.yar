rule EPWIC_15_tap_hi_filter__flt32___32_lil_60_ {
  strings:
    $a0 = { e5 83 a3 3a ad 84 23 bb 45 0c 0f bc df 7e a3 3c 7f f7 4e 3d 6d e3 f6 bd 12 0a 96 be f6 c7 34 3f 12 0a 96 be 6d e3 f6 bd 7f f7 4e 3d df 7e a3 3c 45 0c 0f bc ad 84 23 bb e5 83 a3 3a }

  condition:
    $a0
}