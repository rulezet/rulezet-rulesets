rule TTP_XOR_MULT_DOSStub_a272 {
  strings:
    $key_a272 = { f6 1a [2] 82 02 [2] c5 00 [2] 82 11 [2] cc 1d [2] c0 17 [2] d7 1c [2] cc 52 [2] f1 }

  condition:
    any of them
}