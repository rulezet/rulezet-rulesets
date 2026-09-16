rule TTP_XOR_MULT_DOSStub_a2b9 {
  strings:
    $key_a2b9 = { f6 d1 [2] 82 c9 [2] c5 cb [2] 82 da [2] cc d6 [2] c0 dc [2] d7 d7 [2] cc 99 [2] f1 }

  condition:
    any of them
}