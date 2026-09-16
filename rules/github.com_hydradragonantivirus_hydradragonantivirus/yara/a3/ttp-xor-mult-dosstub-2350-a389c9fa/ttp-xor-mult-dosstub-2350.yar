rule TTP_XOR_MULT_DOSStub_2350 {
  strings:
    $key_2350 = { 77 38 [2] 03 20 [2] 44 22 [2] 03 33 [2] 4d 3f [2] 41 35 [2] 56 3e [2] 4d 70 [2] 70 }

  condition:
    any of them
}