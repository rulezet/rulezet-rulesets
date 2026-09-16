rule TTP_XOR_MULT_DOSStub_a24e {
  strings:
    $key_a24e = { f6 26 [2] 82 3e [2] c5 3c [2] 82 2d [2] cc 21 [2] c0 2b [2] d7 20 [2] cc 6e [2] f1 }

  condition:
    any of them
}