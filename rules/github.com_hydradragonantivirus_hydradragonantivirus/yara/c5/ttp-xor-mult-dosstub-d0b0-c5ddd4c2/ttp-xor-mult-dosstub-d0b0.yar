rule TTP_XOR_MULT_DOSStub_d0b0 {
  strings:
    $key_d0b0 = { 84 d8 [2] f0 c0 [2] b7 c2 [2] f0 d3 [2] be df [2] b2 d5 [2] a5 de [2] be 90 [2] 83 }

  condition:
    any of them
}