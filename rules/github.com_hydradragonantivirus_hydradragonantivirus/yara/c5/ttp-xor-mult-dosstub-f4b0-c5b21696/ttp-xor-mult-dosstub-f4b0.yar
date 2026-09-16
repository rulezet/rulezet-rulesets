rule TTP_XOR_MULT_DOSStub_f4b0 {
  strings:
    $key_f4b0 = { a0 d8 [2] d4 c0 [2] 93 c2 [2] d4 d3 [2] 9a df [2] 96 d5 [2] 81 de [2] 9a 90 [2] a7 }

  condition:
    any of them
}