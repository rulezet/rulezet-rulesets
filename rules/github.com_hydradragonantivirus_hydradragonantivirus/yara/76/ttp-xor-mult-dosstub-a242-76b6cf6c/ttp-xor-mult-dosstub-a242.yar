rule TTP_XOR_MULT_DOSStub_a242 {
  strings:
    $key_a242 = { f6 2a [2] 82 32 [2] c5 30 [2] 82 21 [2] cc 2d [2] c0 27 [2] d7 2c [2] cc 62 [2] f1 }

  condition:
    any of them
}