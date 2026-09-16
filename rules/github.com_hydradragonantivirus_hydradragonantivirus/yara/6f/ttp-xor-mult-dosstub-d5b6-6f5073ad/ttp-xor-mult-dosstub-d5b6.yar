rule TTP_XOR_MULT_DOSStub_d5b6 {
  strings:
    $key_d5b6 = { 81 de [2] f5 c6 [2] b2 c4 [2] f5 d5 [2] bb d9 [2] b7 d3 [2] a0 d8 [2] bb 96 [2] 86 }

  condition:
    any of them
}