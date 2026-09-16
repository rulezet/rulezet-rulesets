rule TTP_XOR_MULT_DOSStub_b885 {
  strings:
    $key_b885 = { ec ed [2] 98 f5 [2] df f7 [2] 98 e6 [2] d6 ea [2] da e0 [2] cd eb [2] d6 a5 [2] eb }

  condition:
    any of them
}