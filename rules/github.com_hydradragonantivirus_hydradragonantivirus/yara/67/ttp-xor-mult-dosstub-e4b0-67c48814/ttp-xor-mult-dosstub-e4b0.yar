rule TTP_XOR_MULT_DOSStub_e4b0 {
  strings:
    $key_e4b0 = { b0 d8 [2] c4 c0 [2] 83 c2 [2] c4 d3 [2] 8a df [2] 86 d5 [2] 91 de [2] 8a 90 [2] b7 }

  condition:
    any of them
}