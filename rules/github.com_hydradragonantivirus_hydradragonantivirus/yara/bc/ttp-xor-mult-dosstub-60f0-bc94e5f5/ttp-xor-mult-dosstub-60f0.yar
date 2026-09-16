rule TTP_XOR_MULT_DOSStub_60f0 {
  strings:
    $key_60f0 = { 34 98 [2] 40 80 [2] 07 82 [2] 40 93 [2] 0e 9f [2] 02 95 [2] 15 9e [2] 0e d0 [2] 33 }

  condition:
    any of them
}