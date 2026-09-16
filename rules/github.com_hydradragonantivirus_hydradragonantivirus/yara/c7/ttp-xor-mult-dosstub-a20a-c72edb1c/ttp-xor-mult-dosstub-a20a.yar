rule TTP_XOR_MULT_DOSStub_a20a {
  strings:
    $key_a20a = { f6 62 [2] 82 7a [2] c5 78 [2] 82 69 [2] cc 65 [2] c0 6f [2] d7 64 [2] cc 2a [2] f1 }

  condition:
    any of them
}