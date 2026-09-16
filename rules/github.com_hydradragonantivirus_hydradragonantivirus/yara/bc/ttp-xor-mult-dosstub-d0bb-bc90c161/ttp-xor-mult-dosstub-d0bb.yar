rule TTP_XOR_MULT_DOSStub_d0bb {
  strings:
    $key_d0bb = { 84 d3 [2] f0 cb [2] b7 c9 [2] f0 d8 [2] be d4 [2] b2 de [2] a5 d5 [2] be 9b [2] 83 }

  condition:
    any of them
}