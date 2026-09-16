rule TTP_XOR_MULT_DOSStub_a381 {
  strings:
    $key_a381 = { f7 e9 [2] 83 f1 [2] c4 f3 [2] 83 e2 [2] cd ee [2] c1 e4 [2] d6 ef [2] cd a1 [2] f0 }

  condition:
    any of them
}