rule TTP_XOR_MULT_DOSStub_c1b6 {
  strings:
    $key_c1b6 = { 95 de [2] e1 c6 [2] a6 c4 [2] e1 d5 [2] af d9 [2] a3 d3 [2] b4 d8 [2] af 96 [2] 92 }

  condition:
    any of them
}