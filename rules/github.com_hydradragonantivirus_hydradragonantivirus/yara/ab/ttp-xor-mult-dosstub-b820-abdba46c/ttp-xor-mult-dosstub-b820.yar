rule TTP_XOR_MULT_DOSStub_b820 {
  strings:
    $key_b820 = { ec 48 [2] 98 50 [2] df 52 [2] 98 43 [2] d6 4f [2] da 45 [2] cd 4e [2] d6 00 [2] eb }

  condition:
    any of them
}