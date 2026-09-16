rule TTP_XOR_MULT_DOSStub_b8f6 {
  strings:
    $key_b8f6 = { ec 9e [2] 98 86 [2] df 84 [2] 98 95 [2] d6 99 [2] da 93 [2] cd 98 [2] d6 d6 [2] eb }

  condition:
    any of them
}