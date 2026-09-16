rule TTP_XOR_MULT_DOSStub_d882 {
  strings:
    $key_d882 = { 8c ea [2] f8 f2 [2] bf f0 [2] f8 e1 [2] b6 ed [2] ba e7 [2] ad ec [2] b6 a2 [2] 8b }

  condition:
    any of them
}