rule TTP_XOR_MULT_DOSStub_a390 {
  strings:
    $key_a390 = { f7 f8 [2] 83 e0 [2] c4 e2 [2] 83 f3 [2] cd ff [2] c1 f5 [2] d6 fe [2] cd b0 [2] f0 }

  condition:
    any of them
}