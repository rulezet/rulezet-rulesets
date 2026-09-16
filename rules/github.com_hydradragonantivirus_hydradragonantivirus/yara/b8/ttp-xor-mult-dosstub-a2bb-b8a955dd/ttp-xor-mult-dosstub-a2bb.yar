rule TTP_XOR_MULT_DOSStub_a2bb {
  strings:
    $key_a2bb = { f6 d3 [2] 82 cb [2] c5 c9 [2] 82 d8 [2] cc d4 [2] c0 de [2] d7 d5 [2] cc 9b [2] f1 }

  condition:
    any of them
}