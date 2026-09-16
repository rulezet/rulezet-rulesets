rule TTP_XOR_MULT_DOSStub_b815 {
  strings:
    $key_b815 = { ec 7d [2] 98 65 [2] df 67 [2] 98 76 [2] d6 7a [2] da 70 [2] cd 7b [2] d6 35 [2] eb }

  condition:
    any of them
}