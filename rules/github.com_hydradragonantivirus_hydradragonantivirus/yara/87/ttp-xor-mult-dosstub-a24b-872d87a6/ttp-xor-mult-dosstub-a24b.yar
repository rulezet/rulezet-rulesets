rule TTP_XOR_MULT_DOSStub_a24b {
  strings:
    $key_a24b = { f6 23 [2] 82 3b [2] c5 39 [2] 82 28 [2] cc 24 [2] c0 2e [2] d7 25 [2] cc 6b [2] f1 }

  condition:
    any of them
}