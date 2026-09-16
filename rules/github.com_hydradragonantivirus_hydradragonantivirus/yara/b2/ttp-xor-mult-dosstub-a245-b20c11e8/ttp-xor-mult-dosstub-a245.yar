rule TTP_XOR_MULT_DOSStub_a245 {
  strings:
    $key_a245 = { f6 2d [2] 82 35 [2] c5 37 [2] 82 26 [2] cc 2a [2] c0 20 [2] d7 2b [2] cc 65 [2] f1 }

  condition:
    any of them
}