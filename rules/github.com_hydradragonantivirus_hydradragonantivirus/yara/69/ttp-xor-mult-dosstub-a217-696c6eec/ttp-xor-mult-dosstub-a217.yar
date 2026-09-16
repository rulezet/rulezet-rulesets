rule TTP_XOR_MULT_DOSStub_a217 {
  strings:
    $key_a217 = { f6 7f [2] 82 67 [2] c5 65 [2] 82 74 [2] cc 78 [2] c0 72 [2] d7 79 [2] cc 37 [2] f1 }

  condition:
    any of them
}