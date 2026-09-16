rule TTP_XOR_MULT_DOSStub_f7b6 {
  strings:
    $key_f7b6 = { a3 de [2] d7 c6 [2] 90 c4 [2] d7 d5 [2] 99 d9 [2] 95 d3 [2] 82 d8 [2] 99 96 [2] a4 }

  condition:
    any of them
}