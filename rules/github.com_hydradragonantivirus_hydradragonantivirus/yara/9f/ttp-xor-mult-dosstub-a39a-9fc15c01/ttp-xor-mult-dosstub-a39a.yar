rule TTP_XOR_MULT_DOSStub_a39a {
  strings:
    $key_a39a = { f7 f2 [2] 83 ea [2] c4 e8 [2] 83 f9 [2] cd f5 [2] c1 ff [2] d6 f4 [2] cd ba [2] f0 }

  condition:
    any of them
}