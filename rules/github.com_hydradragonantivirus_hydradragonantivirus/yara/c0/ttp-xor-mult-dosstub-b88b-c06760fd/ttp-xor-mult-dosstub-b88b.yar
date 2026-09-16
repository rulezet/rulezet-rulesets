rule TTP_XOR_MULT_DOSStub_b88b {
  strings:
    $key_b88b = { ec e3 [2] 98 fb [2] df f9 [2] 98 e8 [2] d6 e4 [2] da ee [2] cd e5 [2] d6 ab [2] eb }

  condition:
    any of them
}