rule TTP_XOR_MULT_DOSStub_f3b6 {
  strings:
    $key_f3b6 = { a7 de [2] d3 c6 [2] 94 c4 [2] d3 d5 [2] 9d d9 [2] 91 d3 [2] 86 d8 [2] 9d 96 [2] a0 }

  condition:
    any of them
}