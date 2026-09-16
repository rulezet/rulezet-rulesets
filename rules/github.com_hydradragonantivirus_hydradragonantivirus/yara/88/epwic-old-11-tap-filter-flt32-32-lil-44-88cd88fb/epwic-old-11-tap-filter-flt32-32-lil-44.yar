rule EPWIC_old_11_tap_filter__flt32___32_lil_44_ {
  strings:
    $a0 = { 1a df 02 3c 5b cb a4 3c 0a 72 4d bd ca 68 fe bd 48 97 95 3e 7d 4d 35 3f 48 97 95 3e ca 68 fe bd 0a 72 4d bd 5b cb a4 3c 1a df 02 3c }

  condition:
    $a0
}