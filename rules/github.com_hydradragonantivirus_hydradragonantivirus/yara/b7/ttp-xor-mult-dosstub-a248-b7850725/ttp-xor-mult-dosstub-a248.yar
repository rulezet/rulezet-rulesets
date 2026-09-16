rule TTP_XOR_MULT_DOSStub_a248 {
  strings:
    $key_a248 = { f6 20 [2] 82 38 [2] c5 3a [2] 82 2b [2] cc 27 [2] c0 2d [2] d7 26 [2] cc 68 [2] f1 }

  condition:
    any of them
}