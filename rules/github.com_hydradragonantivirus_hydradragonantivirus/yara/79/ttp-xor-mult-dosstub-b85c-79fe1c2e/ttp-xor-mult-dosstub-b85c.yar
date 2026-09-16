rule TTP_XOR_MULT_DOSStub_b85c {
  strings:
    $key_b85c = { ec 34 [2] 98 2c [2] df 2e [2] 98 3f [2] d6 33 [2] da 39 [2] cd 32 [2] d6 7c [2] eb }

  condition:
    any of them
}