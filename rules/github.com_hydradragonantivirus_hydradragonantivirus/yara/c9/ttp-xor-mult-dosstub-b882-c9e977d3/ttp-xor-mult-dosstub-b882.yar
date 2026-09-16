rule TTP_XOR_MULT_DOSStub_b882 {
  strings:
    $key_b882 = { ec ea [2] 98 f2 [2] df f0 [2] 98 e1 [2] d6 ed [2] da e7 [2] cd ec [2] d6 a2 [2] eb }

  condition:
    any of them
}