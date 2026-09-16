rule TTP_XOR_MULT_DOSStub_a249 {
  strings:
    $key_a249 = { f6 21 [2] 82 39 [2] c5 3b [2] 82 2a [2] cc 26 [2] c0 2c [2] d7 27 [2] cc 69 [2] f1 }

  condition:
    any of them
}