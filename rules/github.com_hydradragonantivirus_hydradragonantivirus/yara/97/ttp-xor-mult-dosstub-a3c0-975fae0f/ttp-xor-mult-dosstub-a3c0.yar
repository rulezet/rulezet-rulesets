rule TTP_XOR_MULT_DOSStub_a3c0 {
  strings:
    $key_a3c0 = { f7 a8 [2] 83 b0 [2] c4 b2 [2] 83 a3 [2] cd af [2] c1 a5 [2] d6 ae [2] cd e0 [2] f0 }

  condition:
    any of them
}