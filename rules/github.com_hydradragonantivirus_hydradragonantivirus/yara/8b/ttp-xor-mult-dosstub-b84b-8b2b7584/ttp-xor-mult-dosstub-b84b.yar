rule TTP_XOR_MULT_DOSStub_b84b {
  strings:
    $key_b84b = { ec 23 [2] 98 3b [2] df 39 [2] 98 28 [2] d6 24 [2] da 2e [2] cd 25 [2] d6 6b [2] eb }

  condition:
    any of them
}