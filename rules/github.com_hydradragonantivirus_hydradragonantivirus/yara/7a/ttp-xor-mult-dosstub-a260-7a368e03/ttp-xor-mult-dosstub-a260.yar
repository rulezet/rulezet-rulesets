rule TTP_XOR_MULT_DOSStub_a260 {
  strings:
    $key_a260 = { f6 08 [2] 82 10 [2] c5 12 [2] 82 03 [2] cc 0f [2] c0 05 [2] d7 0e [2] cc 40 [2] f1 }

  condition:
    any of them
}