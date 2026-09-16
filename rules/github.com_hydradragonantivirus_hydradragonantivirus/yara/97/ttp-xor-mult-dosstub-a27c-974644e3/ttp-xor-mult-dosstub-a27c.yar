rule TTP_XOR_MULT_DOSStub_a27c {
  strings:
    $key_a27c = { f6 14 [2] 82 0c [2] c5 0e [2] 82 1f [2] cc 13 [2] c0 19 [2] d7 12 [2] cc 5c [2] f1 }

  condition:
    any of them
}