rule TTP_XOR_MULT_DOSStub_a3ce {
  strings:
    $key_a3ce = { f7 a6 [2] 83 be [2] c4 bc [2] 83 ad [2] cd a1 [2] c1 ab [2] d6 a0 [2] cd ee [2] f0 }

  condition:
    any of them
}