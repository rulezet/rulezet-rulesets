rule TTP_XOR_MULT_DOSStub_0ab6 {
  strings:
    $key_0ab6 = { 5e de [2] 2a c6 [2] 6d c4 [2] 2a d5 [2] 64 d9 [2] 68 d3 [2] 7f d8 [2] 64 96 [2] 59 }

  condition:
    any of them
}