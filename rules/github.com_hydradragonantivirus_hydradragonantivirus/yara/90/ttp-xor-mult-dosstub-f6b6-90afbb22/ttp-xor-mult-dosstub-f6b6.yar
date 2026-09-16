rule TTP_XOR_MULT_DOSStub_f6b6 {
  strings:
    $key_f6b6 = { a2 de [2] d6 c6 [2] 91 c4 [2] d6 d5 [2] 98 d9 [2] 94 d3 [2] 83 d8 [2] 98 96 [2] a5 }

  condition:
    any of them
}