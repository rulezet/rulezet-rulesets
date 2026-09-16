rule TTP_XOR_MULT_DOSStub_3db6 {
  strings:
    $key_3db6 = { 69 de [2] 1d c6 [2] 5a c4 [2] 1d d5 [2] 53 d9 [2] 5f d3 [2] 48 d8 [2] 53 96 [2] 6e }

  condition:
    any of them
}