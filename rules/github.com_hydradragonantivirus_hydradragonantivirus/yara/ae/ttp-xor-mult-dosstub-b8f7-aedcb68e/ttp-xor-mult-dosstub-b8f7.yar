rule TTP_XOR_MULT_DOSStub_b8f7 {
  strings:
    $key_b8f7 = { ec 9f [2] 98 87 [2] df 85 [2] 98 94 [2] d6 98 [2] da 92 [2] cd 99 [2] d6 d7 [2] eb }

  condition:
    any of them
}