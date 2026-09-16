rule TTP_XOR_MULT_DOSStub_e4b6 {
  strings:
    $key_e4b6 = { b0 de [2] c4 c6 [2] 83 c4 [2] c4 d5 [2] 8a d9 [2] 86 d3 [2] 91 d8 [2] 8a 96 [2] b7 }

  condition:
    any of them
}