rule TTP_XOR_MULT_DOSStub_f1b6 {
  strings:
    $key_f1b6 = { a5 de [2] d1 c6 [2] 96 c4 [2] d1 d5 [2] 9f d9 [2] 93 d3 [2] 84 d8 [2] 9f 96 [2] a2 }

  condition:
    any of them
}