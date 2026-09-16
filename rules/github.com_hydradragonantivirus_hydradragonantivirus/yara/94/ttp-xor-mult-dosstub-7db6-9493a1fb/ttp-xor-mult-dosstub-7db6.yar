rule TTP_XOR_MULT_DOSStub_7db6 {
  strings:
    $key_7db6 = { 29 de [2] 5d c6 [2] 1a c4 [2] 5d d5 [2] 13 d9 [2] 1f d3 [2] 08 d8 [2] 13 96 [2] 2e }

  condition:
    any of them
}