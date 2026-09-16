rule TTP_XOR_MULT_DOSStub_b84e {
  strings:
    $key_b84e = { ec 26 [2] 98 3e [2] df 3c [2] 98 2d [2] d6 21 [2] da 2b [2] cd 20 [2] d6 6e [2] eb }

  condition:
    any of them
}