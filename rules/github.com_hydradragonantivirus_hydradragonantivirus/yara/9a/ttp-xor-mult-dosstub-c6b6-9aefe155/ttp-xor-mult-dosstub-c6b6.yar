rule TTP_XOR_MULT_DOSStub_c6b6 {
  strings:
    $key_c6b6 = { 92 de [2] e6 c6 [2] a1 c4 [2] e6 d5 [2] a8 d9 [2] a4 d3 [2] b3 d8 [2] a8 96 [2] 95 }

  condition:
    any of them
}