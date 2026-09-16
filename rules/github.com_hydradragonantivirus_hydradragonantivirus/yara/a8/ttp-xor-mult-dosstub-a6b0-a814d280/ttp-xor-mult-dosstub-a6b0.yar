rule TTP_XOR_MULT_DOSStub_a6b0 {
  strings:
    $key_a6b0 = { f2 d8 [2] 86 c0 [2] c1 c2 [2] 86 d3 [2] c8 df [2] c4 d5 [2] d3 de [2] c8 90 [2] f5 }

  condition:
    any of them
}