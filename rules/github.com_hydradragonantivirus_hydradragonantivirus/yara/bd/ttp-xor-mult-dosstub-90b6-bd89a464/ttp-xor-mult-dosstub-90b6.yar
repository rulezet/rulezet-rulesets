rule TTP_XOR_MULT_DOSStub_90b6 {
  strings:
    $key_90b6 = { c4 de [2] b0 c6 [2] f7 c4 [2] b0 d5 [2] fe d9 [2] f2 d3 [2] e5 d8 [2] fe 96 [2] c3 }

  condition:
    any of them
}