rule TTP_XOR_MULT_DOSStub_a24d {
  strings:
    $key_a24d = { f6 25 [2] 82 3d [2] c5 3f [2] 82 2e [2] cc 22 [2] c0 28 [2] d7 23 [2] cc 6d [2] f1 }

  condition:
    any of them
}