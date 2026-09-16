rule TTP_XOR_MULT_DOSStub_4db6 {
  strings:
    $key_4db6 = { 19 de [2] 6d c6 [2] 2a c4 [2] 6d d5 [2] 23 d9 [2] 2f d3 [2] 38 d8 [2] 23 96 [2] 1e }

  condition:
    any of them
}