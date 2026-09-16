rule TTP_XOR_MULT_DOSStub_b8e0 {
  strings:
    $key_b8e0 = { ec 88 [2] 98 90 [2] df 92 [2] 98 83 [2] d6 8f [2] da 85 [2] cd 8e [2] d6 c0 [2] eb }

  condition:
    any of them
}