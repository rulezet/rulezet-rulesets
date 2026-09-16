rule TTP_XOR_MULT_DOSStub_a256 {
  strings:
    $key_a256 = { f6 3e [2] 82 26 [2] c5 24 [2] 82 35 [2] cc 39 [2] c0 33 [2] d7 38 [2] cc 76 [2] f1 }

  condition:
    any of them
}