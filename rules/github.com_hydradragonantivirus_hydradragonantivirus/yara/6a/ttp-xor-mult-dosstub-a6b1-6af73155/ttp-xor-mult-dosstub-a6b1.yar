rule TTP_XOR_MULT_DOSStub_a6b1 {
  strings:
    $key_a6b1 = { f2 d9 [2] 86 c1 [2] c1 c3 [2] 86 d2 [2] c8 de [2] c4 d4 [2] d3 df [2] c8 91 [2] f5 }

  condition:
    any of them
}