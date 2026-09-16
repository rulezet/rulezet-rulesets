rule TTP_XOR_MULT_DOSStub_a2b6 {
  strings:
    $key_a2b6 = { f6 de [2] 82 c6 [2] c5 c4 [2] 82 d5 [2] cc d9 [2] c0 d3 [2] d7 d8 [2] cc 96 [2] f1 }

  condition:
    any of them
}