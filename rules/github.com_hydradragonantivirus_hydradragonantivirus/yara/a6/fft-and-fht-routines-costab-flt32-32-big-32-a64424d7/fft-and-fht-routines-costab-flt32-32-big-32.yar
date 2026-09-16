rule FFT_and_FHT_routines_costab__flt32___32_big_32_ {
  strings:
    $a0 = { 3f 6c 83 5e 3e c3 ef 15 3f 7e c4 6d 3d c8 bd 36 3f 7f ec 43 3c c9 0a b0 3f 7f fe c4 3b c9 0f 88 }

  condition:
    $a0
}