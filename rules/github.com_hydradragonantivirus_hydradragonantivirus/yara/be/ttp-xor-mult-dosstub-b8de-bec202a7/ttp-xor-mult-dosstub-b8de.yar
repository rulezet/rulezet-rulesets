rule TTP_XOR_MULT_DOSStub_b8de {
  strings:
    $key_b8de = { ec b6 [2] 98 ae [2] df ac [2] 98 bd [2] d6 b1 [2] da bb [2] cd b0 [2] d6 fe [2] eb }

  condition:
    any of them
}