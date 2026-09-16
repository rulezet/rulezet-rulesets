rule TTP_XOR_MULT_DOSStub_a24f {
  strings:
    $key_a24f = { f6 27 [2] 82 3f [2] c5 3d [2] 82 2c [2] cc 20 [2] c0 2a [2] d7 21 [2] cc 6f [2] f1 }

  condition:
    any of them
}