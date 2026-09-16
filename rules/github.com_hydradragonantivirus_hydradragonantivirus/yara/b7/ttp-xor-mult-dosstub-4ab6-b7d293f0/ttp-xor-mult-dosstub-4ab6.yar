rule TTP_XOR_MULT_DOSStub_4ab6 {
  strings:
    $key_4ab6 = { 1e de [2] 6a c6 [2] 2d c4 [2] 6a d5 [2] 24 d9 [2] 28 d3 [2] 3f d8 [2] 24 96 [2] 19 }

  condition:
    any of them
}