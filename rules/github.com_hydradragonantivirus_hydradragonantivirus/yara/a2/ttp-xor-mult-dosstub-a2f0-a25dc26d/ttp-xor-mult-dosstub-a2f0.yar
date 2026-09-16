rule TTP_XOR_MULT_DOSStub_a2f0 {
  strings:
    $key_a2f0 = { f6 98 [2] 82 80 [2] c5 82 [2] 82 93 [2] cc 9f [2] c0 95 [2] d7 9e [2] cc d0 [2] f1 }

  condition:
    any of them
}