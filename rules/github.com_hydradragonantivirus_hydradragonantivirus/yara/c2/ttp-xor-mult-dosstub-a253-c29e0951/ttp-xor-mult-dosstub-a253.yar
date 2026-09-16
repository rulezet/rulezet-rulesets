rule TTP_XOR_MULT_DOSStub_a253 {
  strings:
    $key_a253 = { f6 3b [2] 82 23 [2] c5 21 [2] 82 30 [2] cc 3c [2] c0 36 [2] d7 3d [2] cc 73 [2] f1 }

  condition:
    any of them
}