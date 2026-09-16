rule TTP_XOR_MULT_DOSStub_a25b {
  strings:
    $key_a25b = { f6 33 [2] 82 2b [2] c5 29 [2] 82 38 [2] cc 34 [2] c0 3e [2] d7 35 [2] cc 7b [2] f1 }

  condition:
    any of them
}