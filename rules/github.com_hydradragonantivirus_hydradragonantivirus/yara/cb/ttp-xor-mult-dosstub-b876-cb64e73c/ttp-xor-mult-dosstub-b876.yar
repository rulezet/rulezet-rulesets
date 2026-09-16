rule TTP_XOR_MULT_DOSStub_b876 {
  strings:
    $key_b876 = { ec 1e [2] 98 06 [2] df 04 [2] 98 15 [2] d6 19 [2] da 13 [2] cd 18 [2] d6 56 [2] eb }

  condition:
    any of them
}