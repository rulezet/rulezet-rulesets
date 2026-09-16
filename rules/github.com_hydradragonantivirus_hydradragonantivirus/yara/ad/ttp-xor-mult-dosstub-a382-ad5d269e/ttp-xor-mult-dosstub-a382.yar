rule TTP_XOR_MULT_DOSStub_a382 {
  strings:
    $key_a382 = { f7 ea [2] 83 f2 [2] c4 f0 [2] 83 e1 [2] cd ed [2] c1 e7 [2] d6 ec [2] cd a2 [2] f0 }

  condition:
    any of them
}