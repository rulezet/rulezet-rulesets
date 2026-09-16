rule TTP_XOR_MULT_DOSStub_d552 {
  strings:
    $key_d552 = { 81 3a [2] f5 22 [2] b2 20 [2] f5 31 [2] bb 3d [2] b7 37 [2] a0 3c [2] bb 72 [2] 86 }

  condition:
    any of them
}