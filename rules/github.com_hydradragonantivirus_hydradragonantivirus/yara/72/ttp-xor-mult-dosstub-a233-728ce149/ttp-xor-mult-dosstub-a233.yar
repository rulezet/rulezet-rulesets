rule TTP_XOR_MULT_DOSStub_a233 {
  strings:
    $key_a233 = { f6 5b [2] 82 43 [2] c5 41 [2] 82 50 [2] cc 5c [2] c0 56 [2] d7 5d [2] cc 13 [2] f1 }

  condition:
    any of them
}