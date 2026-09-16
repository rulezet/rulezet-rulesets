rule TTP_XOR_MULT_DOSStub_a2f2 {
  strings:
    $key_a2f2 = { f6 9a [2] 82 82 [2] c5 80 [2] 82 91 [2] cc 9d [2] c0 97 [2] d7 9c [2] cc d2 [2] f1 }

  condition:
    any of them
}