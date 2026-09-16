rule TTP_XOR_MULT_DOSStub_b847 {
  strings:
    $key_b847 = { ec 2f [2] 98 37 [2] df 35 [2] 98 24 [2] d6 28 [2] da 22 [2] cd 29 [2] d6 67 [2] eb }

  condition:
    any of them
}