rule TTP_XOR_MULT_DOSStub_b81e {
  strings:
    $key_b81e = { ec 76 [2] 98 6e [2] df 6c [2] 98 7d [2] d6 71 [2] da 7b [2] cd 70 [2] d6 3e [2] eb }

  condition:
    any of them
}