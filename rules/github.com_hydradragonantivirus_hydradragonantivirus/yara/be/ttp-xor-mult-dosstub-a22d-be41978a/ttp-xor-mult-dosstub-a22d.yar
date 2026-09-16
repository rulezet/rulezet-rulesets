rule TTP_XOR_MULT_DOSStub_a22d {
  strings:
    $key_a22d = { f6 45 [2] 82 5d [2] c5 5f [2] 82 4e [2] cc 42 [2] c0 48 [2] d7 43 [2] cc 0d [2] f1 }

  condition:
    any of them
}