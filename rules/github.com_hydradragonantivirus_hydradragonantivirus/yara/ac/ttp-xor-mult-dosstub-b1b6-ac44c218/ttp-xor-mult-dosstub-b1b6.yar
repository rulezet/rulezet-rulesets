rule TTP_XOR_MULT_DOSStub_b1b6 {
  strings:
    $key_b1b6 = { e5 de [2] 91 c6 [2] d6 c4 [2] 91 d5 [2] df d9 [2] d3 d3 [2] c4 d8 [2] df 96 [2] e2 }

  condition:
    any of them
}