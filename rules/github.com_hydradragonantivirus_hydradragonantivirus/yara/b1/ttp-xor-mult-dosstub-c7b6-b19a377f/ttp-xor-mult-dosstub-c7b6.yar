rule TTP_XOR_MULT_DOSStub_c7b6 {
  strings:
    $key_c7b6 = { 93 de [2] e7 c6 [2] a0 c4 [2] e7 d5 [2] a9 d9 [2] a5 d3 [2] b2 d8 [2] a9 96 [2] 94 }

  condition:
    any of them
}