rule TTP_XOR_MULT_DOSStub_aa82 {
  strings:
    $key_aa82 = { fe ea [2] 8a f2 [2] cd f0 [2] 8a e1 [2] c4 ed [2] c8 e7 [2] df ec [2] c4 a2 [2] f9 }

  condition:
    any of them
}