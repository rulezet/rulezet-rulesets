rule TTP_XOR_MULT_DOSStub_a27a {
  strings:
    $key_a27a = { f6 12 [2] 82 0a [2] c5 08 [2] 82 19 [2] cc 15 [2] c0 1f [2] d7 14 [2] cc 5a [2] f1 }

  condition:
    any of them
}