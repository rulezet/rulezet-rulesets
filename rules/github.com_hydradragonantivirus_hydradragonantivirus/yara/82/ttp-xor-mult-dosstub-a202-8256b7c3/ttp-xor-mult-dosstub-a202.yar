rule TTP_XOR_MULT_DOSStub_a202 {
  strings:
    $key_a202 = { f6 6a [2] 82 72 [2] c5 70 [2] 82 61 [2] cc 6d [2] c0 67 [2] d7 6c [2] cc 22 [2] f1 }

  condition:
    any of them
}