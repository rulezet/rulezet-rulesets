rule TTP_XOR_MULT_DOSStub_a261 {
  strings:
    $key_a261 = { f6 09 [2] 82 11 [2] c5 13 [2] 82 02 [2] cc 0e [2] c0 04 [2] d7 0f [2] cc 41 [2] f1 }

  condition:
    any of them
}