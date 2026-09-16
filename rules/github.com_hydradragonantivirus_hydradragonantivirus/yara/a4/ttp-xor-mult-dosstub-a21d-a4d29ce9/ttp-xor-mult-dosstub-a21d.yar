rule TTP_XOR_MULT_DOSStub_a21d {
  strings:
    $key_a21d = { f6 75 [2] 82 6d [2] c5 6f [2] 82 7e [2] cc 72 [2] c0 78 [2] d7 73 [2] cc 3d [2] f1 }

  condition:
    any of them
}