rule TTP_XOR_MULT_DOSStub_a27d {
  strings:
    $key_a27d = { f6 15 [2] 82 0d [2] c5 0f [2] 82 1e [2] cc 12 [2] c0 18 [2] d7 13 [2] cc 5d [2] f1 }

  condition:
    any of them
}