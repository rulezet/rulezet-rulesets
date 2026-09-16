rule TTP_XOR_MULT_DOSStub_a642 {
  strings:
    $key_a642 = { f2 2a [2] 86 32 [2] c1 30 [2] 86 21 [2] c8 2d [2] c4 27 [2] d3 2c [2] c8 62 [2] f5 }

  condition:
    any of them
}