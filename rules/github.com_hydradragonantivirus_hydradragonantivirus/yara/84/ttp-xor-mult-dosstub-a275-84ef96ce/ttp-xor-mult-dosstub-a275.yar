rule TTP_XOR_MULT_DOSStub_a275 {
  strings:
    $key_a275 = { f6 1d [2] 82 05 [2] c5 07 [2] 82 16 [2] cc 1a [2] c0 10 [2] d7 1b [2] cc 55 [2] f1 }

  condition:
    any of them
}