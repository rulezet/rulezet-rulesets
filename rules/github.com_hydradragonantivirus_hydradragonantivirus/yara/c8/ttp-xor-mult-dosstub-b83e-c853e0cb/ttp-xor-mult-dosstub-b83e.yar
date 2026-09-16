rule TTP_XOR_MULT_DOSStub_b83e {
  strings:
    $key_b83e = { ec 56 [2] 98 4e [2] df 4c [2] 98 5d [2] d6 51 [2] da 5b [2] cd 50 [2] d6 1e [2] eb }

  condition:
    any of them
}