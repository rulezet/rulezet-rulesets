rule TTP_XOR_MULT_DOSStub_8eb6 {
  strings:
    $key_8eb6 = { da de [2] ae c6 [2] e9 c4 [2] ae d5 [2] e0 d9 [2] ec d3 [2] fb d8 [2] e0 96 [2] dd }

  condition:
    any of them
}