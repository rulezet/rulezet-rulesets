rule TTP_XOR_MULT_DOSStub_e7b0 {
  strings:
    $key_e7b0 = { b3 d8 [2] c7 c0 [2] 80 c2 [2] c7 d3 [2] 89 df [2] 85 d5 [2] 92 de [2] 89 90 [2] b4 }

  condition:
    any of them
}