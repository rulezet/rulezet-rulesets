rule TTP_XOR_MULT_DOSStub_2372 {
  strings:
    $key_2372 = { 77 1a [2] 03 02 [2] 44 00 [2] 03 11 [2] 4d 1d [2] 41 17 [2] 56 1c [2] 4d 52 [2] 70 }

  condition:
    any of them
}