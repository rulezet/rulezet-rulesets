rule TTP_XOR_MULT_DOSStub_b82d {
  strings:
    $key_b82d = { ec 45 [2] 98 5d [2] df 5f [2] 98 4e [2] d6 42 [2] da 48 [2] cd 43 [2] d6 0d [2] eb }

  condition:
    any of them
}