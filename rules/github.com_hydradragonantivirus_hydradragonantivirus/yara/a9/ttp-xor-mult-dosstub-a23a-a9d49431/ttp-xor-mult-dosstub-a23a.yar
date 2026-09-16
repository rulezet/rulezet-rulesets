rule TTP_XOR_MULT_DOSStub_a23a {
  strings:
    $key_a23a = { f6 52 [2] 82 4a [2] c5 48 [2] 82 59 [2] cc 55 [2] c0 5f [2] d7 54 [2] cc 1a [2] f1 }

  condition:
    any of them
}