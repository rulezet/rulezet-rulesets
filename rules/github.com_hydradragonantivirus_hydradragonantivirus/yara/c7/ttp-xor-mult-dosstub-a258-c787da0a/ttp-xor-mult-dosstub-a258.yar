rule TTP_XOR_MULT_DOSStub_a258 {
  strings:
    $key_a258 = { f6 30 [2] 82 28 [2] c5 2a [2] 82 3b [2] cc 37 [2] c0 3d [2] d7 36 [2] cc 78 [2] f1 }

  condition:
    any of them
}