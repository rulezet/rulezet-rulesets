rule TTP_XOR_MULT_DOSStub_3ab6 {
  strings:
    $key_3ab6 = { 6e de [2] 1a c6 [2] 5d c4 [2] 1a d5 [2] 54 d9 [2] 58 d3 [2] 4f d8 [2] 54 96 [2] 69 }

  condition:
    any of them
}