rule TTP_XOR_MULT_DOSStub_b80b {
  strings:
    $key_b80b = { ec 63 [2] 98 7b [2] df 79 [2] 98 68 [2] d6 64 [2] da 6e [2] cd 65 [2] d6 2b [2] eb }

  condition:
    any of them
}