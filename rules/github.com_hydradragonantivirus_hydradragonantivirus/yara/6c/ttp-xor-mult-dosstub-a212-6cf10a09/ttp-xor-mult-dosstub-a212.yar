rule TTP_XOR_MULT_DOSStub_a212 {
  strings:
    $key_a212 = { f6 7a [2] 82 62 [2] c5 60 [2] 82 71 [2] cc 7d [2] c0 77 [2] d7 7c [2] cc 32 [2] f1 }

  condition:
    any of them
}