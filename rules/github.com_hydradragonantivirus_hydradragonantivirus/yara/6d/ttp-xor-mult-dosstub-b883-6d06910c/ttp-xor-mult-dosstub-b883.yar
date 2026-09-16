rule TTP_XOR_MULT_DOSStub_b883 {
  strings:
    $key_b883 = { ec eb [2] 98 f3 [2] df f1 [2] 98 e0 [2] d6 ec [2] da e6 [2] cd ed [2] d6 a3 [2] eb }

  condition:
    any of them
}