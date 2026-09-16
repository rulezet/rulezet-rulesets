rule TTP_XOR_MULT_DOSStub_a380 {
  strings:
    $key_a380 = { f7 e8 [2] 83 f0 [2] c4 f2 [2] 83 e3 [2] cd ef [2] c1 e5 [2] d6 ee [2] cd a0 [2] f0 }

  condition:
    any of them
}