rule TTP_XOR_MULT_DOSStub_92b0 {
  strings:
    $key_92b0 = { c6 d8 [2] b2 c0 [2] f5 c2 [2] b2 d3 [2] fc df [2] f0 d5 [2] e7 de [2] fc 90 [2] c1 }

  condition:
    any of them
}