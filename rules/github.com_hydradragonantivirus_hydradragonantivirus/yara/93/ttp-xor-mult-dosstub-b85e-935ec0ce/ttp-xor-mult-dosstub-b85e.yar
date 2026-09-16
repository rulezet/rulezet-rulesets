rule TTP_XOR_MULT_DOSStub_b85e {
  strings:
    $key_b85e = { ec 36 [2] 98 2e [2] df 2c [2] 98 3d [2] d6 31 [2] da 3b [2] cd 30 [2] d6 7e [2] eb }

  condition:
    any of them
}