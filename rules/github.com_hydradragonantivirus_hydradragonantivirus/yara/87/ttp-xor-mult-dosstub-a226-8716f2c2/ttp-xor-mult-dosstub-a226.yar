rule TTP_XOR_MULT_DOSStub_a226 {
  strings:
    $key_a226 = { f6 4e [2] 82 56 [2] c5 54 [2] 82 45 [2] cc 49 [2] c0 43 [2] d7 48 [2] cc 06 [2] f1 }

  condition:
    any of them
}