rule TTP_XOR_MULT_DOSStub_b848 {
  strings:
    $key_b848 = { ec 20 [2] 98 38 [2] df 3a [2] 98 2b [2] d6 27 [2] da 2d [2] cd 26 [2] d6 68 [2] eb }

  condition:
    any of them
}