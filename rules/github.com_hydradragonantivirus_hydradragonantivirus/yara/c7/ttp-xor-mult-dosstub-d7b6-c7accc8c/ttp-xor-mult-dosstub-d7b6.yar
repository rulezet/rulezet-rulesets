rule TTP_XOR_MULT_DOSStub_d7b6 {
  strings:
    $key_d7b6 = { 83 de [2] f7 c6 [2] b0 c4 [2] f7 d5 [2] b9 d9 [2] b5 d3 [2] a2 d8 [2] b9 96 [2] 84 }

  condition:
    any of them
}