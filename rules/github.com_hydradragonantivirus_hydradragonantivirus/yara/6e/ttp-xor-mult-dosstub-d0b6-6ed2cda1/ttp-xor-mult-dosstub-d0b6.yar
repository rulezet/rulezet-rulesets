rule TTP_XOR_MULT_DOSStub_d0b6 {
  strings:
    $key_d0b6 = { 84 de [2] f0 c6 [2] b7 c4 [2] f0 d5 [2] be d9 [2] b2 d3 [2] a5 d8 [2] be 96 [2] 83 }

  condition:
    any of them
}