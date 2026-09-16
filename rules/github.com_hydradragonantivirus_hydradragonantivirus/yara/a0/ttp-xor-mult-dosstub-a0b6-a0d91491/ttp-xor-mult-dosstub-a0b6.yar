rule TTP_XOR_MULT_DOSStub_a0b6 {
  strings:
    $key_a0b6 = { f4 de [2] 80 c6 [2] c7 c4 [2] 80 d5 [2] ce d9 [2] c2 d3 [2] d5 d8 [2] ce 96 [2] f3 }

  condition:
    any of them
}