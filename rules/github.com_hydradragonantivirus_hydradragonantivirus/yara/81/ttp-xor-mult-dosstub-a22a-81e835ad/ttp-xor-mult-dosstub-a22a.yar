rule TTP_XOR_MULT_DOSStub_a22a {
  strings:
    $key_a22a = { f6 42 [2] 82 5a [2] c5 58 [2] 82 49 [2] cc 45 [2] c0 4f [2] d7 44 [2] cc 0a [2] f1 }

  condition:
    any of them
}