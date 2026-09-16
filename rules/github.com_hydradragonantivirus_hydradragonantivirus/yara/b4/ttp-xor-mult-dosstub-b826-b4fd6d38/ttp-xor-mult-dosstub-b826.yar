rule TTP_XOR_MULT_DOSStub_b826 {
  strings:
    $key_b826 = { ec 4e [2] 98 56 [2] df 54 [2] 98 45 [2] d6 49 [2] da 43 [2] cd 48 [2] d6 06 [2] eb }

  condition:
    any of them
}