rule TTP_XOR_MULT_DOSStub_f4b6 {
  strings:
    $key_f4b6 = { a0 de [2] d4 c6 [2] 93 c4 [2] d4 d5 [2] 9a d9 [2] 96 d3 [2] 81 d8 [2] 9a 96 [2] a7 }

  condition:
    any of them
}