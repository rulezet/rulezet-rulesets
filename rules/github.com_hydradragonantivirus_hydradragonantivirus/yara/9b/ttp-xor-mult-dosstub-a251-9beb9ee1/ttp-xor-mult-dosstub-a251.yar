rule TTP_XOR_MULT_DOSStub_a251 {
  strings:
    $key_a251 = { f6 39 [2] 82 21 [2] c5 23 [2] 82 32 [2] cc 3e [2] c0 34 [2] d7 3f [2] cc 71 [2] f1 }

  condition:
    any of them
}