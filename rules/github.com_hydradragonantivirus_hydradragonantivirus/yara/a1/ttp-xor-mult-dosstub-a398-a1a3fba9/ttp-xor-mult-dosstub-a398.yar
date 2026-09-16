rule TTP_XOR_MULT_DOSStub_a398 {
  strings:
    $key_a398 = { f7 f0 [2] 83 e8 [2] c4 ea [2] 83 fb [2] cd f7 [2] c1 fd [2] d6 f6 [2] cd b8 [2] f0 }

  condition:
    any of them
}