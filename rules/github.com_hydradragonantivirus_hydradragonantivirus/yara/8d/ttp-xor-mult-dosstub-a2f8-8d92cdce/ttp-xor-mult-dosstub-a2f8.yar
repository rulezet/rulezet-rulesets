rule TTP_XOR_MULT_DOSStub_a2f8 {
  strings:
    $key_a2f8 = { f6 90 [2] 82 88 [2] c5 8a [2] 82 9b [2] cc 97 [2] c0 9d [2] d7 96 [2] cc d8 [2] f1 }

  condition:
    any of them
}