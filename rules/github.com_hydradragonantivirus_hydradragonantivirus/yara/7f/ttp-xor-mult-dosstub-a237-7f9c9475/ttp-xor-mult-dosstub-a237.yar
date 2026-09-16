rule TTP_XOR_MULT_DOSStub_a237 {
  strings:
    $key_a237 = { f6 5f [2] 82 47 [2] c5 45 [2] 82 54 [2] cc 58 [2] c0 52 [2] d7 59 [2] cc 17 [2] f1 }

  condition:
    any of them
}