rule TTP_XOR_MULT_DOSStub_a204 {
  strings:
    $key_a204 = { f6 6c [2] 82 74 [2] c5 76 [2] 82 67 [2] cc 6b [2] c0 61 [2] d7 6a [2] cc 24 [2] f1 }

  condition:
    any of them
}