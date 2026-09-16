rule TTP_XOR_MULT_DOSStub_a2f5 {
  strings:
    $key_a2f5 = { f6 9d [2] 82 85 [2] c5 87 [2] 82 96 [2] cc 9a [2] c0 90 [2] d7 9b [2] cc d5 [2] f1 }

  condition:
    any of them
}