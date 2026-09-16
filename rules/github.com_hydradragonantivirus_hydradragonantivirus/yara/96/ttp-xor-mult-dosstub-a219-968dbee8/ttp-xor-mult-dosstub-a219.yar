rule TTP_XOR_MULT_DOSStub_a219 {
  strings:
    $key_a219 = { f6 71 [2] 82 69 [2] c5 6b [2] 82 7a [2] cc 76 [2] c0 7c [2] d7 77 [2] cc 39 [2] f1 }

  condition:
    any of them
}