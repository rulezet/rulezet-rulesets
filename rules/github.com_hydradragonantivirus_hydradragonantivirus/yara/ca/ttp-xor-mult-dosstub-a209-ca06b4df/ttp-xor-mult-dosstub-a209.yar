rule TTP_XOR_MULT_DOSStub_a209 {
  strings:
    $key_a209 = { f6 61 [2] 82 79 [2] c5 7b [2] 82 6a [2] cc 66 [2] c0 6c [2] d7 67 [2] cc 29 [2] f1 }

  condition:
    any of them
}