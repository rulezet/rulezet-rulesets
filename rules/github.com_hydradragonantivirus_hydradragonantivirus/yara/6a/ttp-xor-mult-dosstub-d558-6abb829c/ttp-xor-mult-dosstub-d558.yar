rule TTP_XOR_MULT_DOSStub_d558 {
  strings:
    $key_d558 = { 81 30 [2] f5 28 [2] b2 2a [2] f5 3b [2] bb 37 [2] b7 3d [2] a0 36 [2] bb 78 [2] 86 }

  condition:
    any of them
}