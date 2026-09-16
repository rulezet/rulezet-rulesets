rule TTP_XOR_MULT_DOSStub_b8e6 {
  strings:
    $key_b8e6 = { ec 8e [2] 98 96 [2] df 94 [2] 98 85 [2] d6 89 [2] da 83 [2] cd 88 [2] d6 c6 [2] eb }

  condition:
    any of them
}