rule TTP_XOR_MULT_DOSStub_e0b6 {
  strings:
    $key_e0b6 = { b4 de [2] c0 c6 [2] 87 c4 [2] c0 d5 [2] 8e d9 [2] 82 d3 [2] 95 d8 [2] 8e 96 [2] b3 }

  condition:
    any of them
}