rule TTP_XOR_MULT_DOSStub_d582 {
  strings:
    $key_d582 = { 81 ea [2] f5 f2 [2] b2 f0 [2] f5 e1 [2] bb ed [2] b7 e7 [2] a0 ec [2] bb a2 [2] 86 }

  condition:
    any of them
}