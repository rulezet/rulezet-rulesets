rule TTP_XOR_MULT_DOSStub_a25e {
  strings:
    $key_a25e = { f6 36 [2] 82 2e [2] c5 2c [2] 82 3d [2] cc 31 [2] c0 3b [2] d7 30 [2] cc 7e [2] f1 }

  condition:
    any of them
}