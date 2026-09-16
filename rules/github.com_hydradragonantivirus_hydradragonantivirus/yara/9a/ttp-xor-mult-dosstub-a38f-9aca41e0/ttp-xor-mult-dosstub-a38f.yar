rule TTP_XOR_MULT_DOSStub_a38f {
  strings:
    $key_a38f = { f7 e7 [2] 83 ff [2] c4 fd [2] 83 ec [2] cd e0 [2] c1 ea [2] d6 e1 [2] cd af [2] f0 }

  condition:
    any of them
}