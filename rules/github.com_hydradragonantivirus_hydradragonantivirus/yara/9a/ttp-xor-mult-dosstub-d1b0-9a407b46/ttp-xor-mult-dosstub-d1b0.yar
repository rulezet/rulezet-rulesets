rule TTP_XOR_MULT_DOSStub_d1b0 {
  strings:
    $key_d1b0 = { 85 d8 [2] f1 c0 [2] b6 c2 [2] f1 d3 [2] bf df [2] b3 d5 [2] a4 de [2] bf 90 [2] 82 }

  condition:
    any of them
}