rule TTP_XOR_MULT_DOSStub_b860 {
  strings:
    $key_b860 = { ec 08 [2] 98 10 [2] df 12 [2] 98 03 [2] d6 0f [2] da 05 [2] cd 0e [2] d6 40 [2] eb }

  condition:
    any of them
}