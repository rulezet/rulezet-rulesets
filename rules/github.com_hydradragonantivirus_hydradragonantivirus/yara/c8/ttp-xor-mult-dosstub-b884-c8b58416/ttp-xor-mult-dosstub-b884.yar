rule TTP_XOR_MULT_DOSStub_b884 {
  strings:
    $key_b884 = { ec ec [2] 98 f4 [2] df f6 [2] 98 e7 [2] d6 eb [2] da e1 [2] cd ea [2] d6 a4 [2] eb }

  condition:
    any of them
}