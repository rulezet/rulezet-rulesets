rule TTP_XOR_MULT_DOSStub_a239 {
  strings:
    $key_a239 = { f6 51 [2] 82 49 [2] c5 4b [2] 82 5a [2] cc 56 [2] c0 5c [2] d7 57 [2] cc 19 [2] f1 }

  condition:
    any of them
}