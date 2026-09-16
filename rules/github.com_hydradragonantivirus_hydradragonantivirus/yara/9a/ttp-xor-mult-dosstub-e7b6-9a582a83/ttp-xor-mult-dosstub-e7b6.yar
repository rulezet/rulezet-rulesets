rule TTP_XOR_MULT_DOSStub_e7b6 {
  strings:
    $key_e7b6 = { b3 de [2] c7 c6 [2] 80 c4 [2] c7 d5 [2] 89 d9 [2] 85 d3 [2] 92 d8 [2] 89 96 [2] b4 }

  condition:
    any of them
}