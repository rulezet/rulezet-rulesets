rule TTP_XOR_MULT_DOSStub_a270 {
  strings:
    $key_a270 = { f6 18 [2] 82 00 [2] c5 02 [2] 82 13 [2] cc 1f [2] c0 15 [2] d7 1e [2] cc 50 [2] f1 }

  condition:
    any of them
}