rule TTP_XOR_MULT_DOSStub_d1b6 {
  strings:
    $key_d1b6 = { 85 de [2] f1 c6 [2] b6 c4 [2] f1 d5 [2] bf d9 [2] b3 d3 [2] a4 d8 [2] bf 96 [2] 82 }

  condition:
    any of them
}