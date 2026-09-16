rule TTP_XOR_MULT_DOSStub_a26a {
  strings:
    $key_a26a = { f6 02 [2] 82 1a [2] c5 18 [2] 82 09 [2] cc 05 [2] c0 0f [2] d7 04 [2] cc 4a [2] f1 }

  condition:
    any of them
}