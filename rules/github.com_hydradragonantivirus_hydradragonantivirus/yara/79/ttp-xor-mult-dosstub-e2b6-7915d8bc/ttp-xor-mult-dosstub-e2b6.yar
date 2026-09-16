rule TTP_XOR_MULT_DOSStub_e2b6 {
  strings:
    $key_e2b6 = { b6 de [2] c2 c6 [2] 85 c4 [2] c2 d5 [2] 8c d9 [2] 80 d3 [2] 97 d8 [2] 8c 96 [2] b1 }

  condition:
    any of them
}