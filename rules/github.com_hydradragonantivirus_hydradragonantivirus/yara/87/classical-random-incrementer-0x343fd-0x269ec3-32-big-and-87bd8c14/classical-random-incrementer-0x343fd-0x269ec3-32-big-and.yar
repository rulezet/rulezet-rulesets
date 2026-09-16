rule classical_random_incrementer_0x343FD_0x269EC3__32_big_AND_ {
  strings:
    $a0 = { 00 03 43 fd [0-20] 00 26 9e c3 }

  condition:
    $a0
}