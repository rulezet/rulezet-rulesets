rule TTP_XOR_MULT_DOSStub_e6b0 {
  strings:
    $key_e6b0 = { b2 d8 [2] c6 c0 [2] 81 c2 [2] c6 d3 [2] 88 df [2] 84 d5 [2] 93 de [2] 88 90 [2] b5 }

  condition:
    any of them
}