rule TTP_XOR_MULT_DOSStub_a3dd {
  strings:
    $key_a3dd = { f7 b5 [2] 83 ad [2] c4 af [2] 83 be [2] cd b2 [2] c1 b8 [2] d6 b3 [2] cd fd [2] f0 }

  condition:
    any of them
}