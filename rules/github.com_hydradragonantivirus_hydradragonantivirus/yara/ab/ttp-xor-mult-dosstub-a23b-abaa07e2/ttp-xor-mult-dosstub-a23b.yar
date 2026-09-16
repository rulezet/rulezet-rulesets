rule TTP_XOR_MULT_DOSStub_a23b {
  strings:
    $key_a23b = { f6 53 [2] 82 4b [2] c5 49 [2] 82 58 [2] cc 54 [2] c0 5e [2] d7 55 [2] cc 1b [2] f1 }

  condition:
    any of them
}