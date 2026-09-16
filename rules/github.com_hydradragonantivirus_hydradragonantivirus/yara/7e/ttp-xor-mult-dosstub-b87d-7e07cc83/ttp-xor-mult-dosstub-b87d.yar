rule TTP_XOR_MULT_DOSStub_b87d {
  strings:
    $key_b87d = { ec 15 [2] 98 0d [2] df 0f [2] 98 1e [2] d6 12 [2] da 18 [2] cd 13 [2] d6 5d [2] eb }

  condition:
    any of them
}