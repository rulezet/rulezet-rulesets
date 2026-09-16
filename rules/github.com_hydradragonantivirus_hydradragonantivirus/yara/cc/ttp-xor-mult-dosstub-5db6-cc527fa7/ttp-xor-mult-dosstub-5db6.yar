rule TTP_XOR_MULT_DOSStub_5db6 {
  strings:
    $key_5db6 = { 09 de [2] 7d c6 [2] 3a c4 [2] 7d d5 [2] 33 d9 [2] 3f d3 [2] 28 d8 [2] 33 96 [2] 0e }

  condition:
    any of them
}