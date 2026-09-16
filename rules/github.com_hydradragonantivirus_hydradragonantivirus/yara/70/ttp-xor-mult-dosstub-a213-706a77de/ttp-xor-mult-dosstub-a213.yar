rule TTP_XOR_MULT_DOSStub_a213 {
  strings:
    $key_a213 = { f6 7b [2] 82 63 [2] c5 61 [2] 82 70 [2] cc 7c [2] c0 76 [2] d7 7d [2] cc 33 [2] f1 }

  condition:
    any of them
}