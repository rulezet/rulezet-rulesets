rule TTP_XOR_MULT_DOSStub_b8e7 {
  strings:
    $key_b8e7 = { ec 8f [2] 98 97 [2] df 95 [2] 98 84 [2] d6 88 [2] da 82 [2] cd 89 [2] d6 c7 [2] eb }

  condition:
    any of them
}