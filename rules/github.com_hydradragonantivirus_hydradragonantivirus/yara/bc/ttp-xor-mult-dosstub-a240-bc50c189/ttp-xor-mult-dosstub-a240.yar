rule TTP_XOR_MULT_DOSStub_a240 {
  strings:
    $key_a240 = { f6 28 [2] 82 30 [2] c5 32 [2] 82 23 [2] cc 2f [2] c0 25 [2] d7 2e [2] cc 60 [2] f1 }

  condition:
    any of them
}