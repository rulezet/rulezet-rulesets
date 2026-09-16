rule TTP_XOR_MULT_DOSStub_96b0 {
  strings:
    $key_96b0 = { c2 d8 [2] b6 c0 [2] f1 c2 [2] b6 d3 [2] f8 df [2] f4 d5 [2] e3 de [2] f8 90 [2] c5 }

  condition:
    any of them
}