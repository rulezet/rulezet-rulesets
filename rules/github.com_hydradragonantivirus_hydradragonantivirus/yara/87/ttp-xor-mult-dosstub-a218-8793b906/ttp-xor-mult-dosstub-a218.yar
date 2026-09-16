rule TTP_XOR_MULT_DOSStub_a218 {
  strings:
    $key_a218 = { f6 70 [2] 82 68 [2] c5 6a [2] 82 7b [2] cc 77 [2] c0 7d [2] d7 76 [2] cc 38 [2] f1 }

  condition:
    any of them
}