rule TTP_XOR_MULT_DOSStub_a383 {
  strings:
    $key_a383 = { f7 eb [2] 83 f3 [2] c4 f1 [2] 83 e0 [2] cd ec [2] c1 e6 [2] d6 ed [2] cd a3 [2] f0 }

  condition:
    any of them
}