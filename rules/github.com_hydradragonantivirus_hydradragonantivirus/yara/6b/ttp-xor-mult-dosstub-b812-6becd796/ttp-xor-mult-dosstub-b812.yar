rule TTP_XOR_MULT_DOSStub_b812 {
  strings:
    $key_b812 = { ec 7a [2] 98 62 [2] df 60 [2] 98 71 [2] d6 7d [2] da 77 [2] cd 7c [2] d6 32 [2] eb }

  condition:
    any of them
}