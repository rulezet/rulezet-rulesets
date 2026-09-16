rule TTP_XOR_MULT_DOSStub_a27e {
  strings:
    $key_a27e = { f6 16 [2] 82 0e [2] c5 0c [2] 82 1d [2] cc 11 [2] c0 1b [2] d7 10 [2] cc 5e [2] f1 }

  condition:
    any of them
}