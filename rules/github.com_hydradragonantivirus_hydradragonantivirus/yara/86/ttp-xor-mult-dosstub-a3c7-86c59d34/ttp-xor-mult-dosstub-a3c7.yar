rule TTP_XOR_MULT_DOSStub_a3c7 {
  strings:
    $key_a3c7 = { f7 af [2] 83 b7 [2] c4 b5 [2] 83 a4 [2] cd a8 [2] c1 a2 [2] d6 a9 [2] cd e7 [2] f0 }

  condition:
    any of them
}