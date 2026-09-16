rule TTP_XOR_MULT_DOSStub_f3b0 {
  strings:
    $key_f3b0 = { a7 d8 [2] d3 c0 [2] 94 c2 [2] d3 d3 [2] 9d df [2] 91 d5 [2] 86 de [2] 9d 90 [2] a0 }

  condition:
    any of them
}