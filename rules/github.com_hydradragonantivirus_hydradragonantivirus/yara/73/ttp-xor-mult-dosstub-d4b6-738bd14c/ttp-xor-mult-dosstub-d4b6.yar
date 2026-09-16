rule TTP_XOR_MULT_DOSStub_d4b6 {
  strings:
    $key_d4b6 = { 80 de [2] f4 c6 [2] b3 c4 [2] f4 d5 [2] ba d9 [2] b6 d3 [2] a1 d8 [2] ba 96 [2] 87 }

  condition:
    any of them
}