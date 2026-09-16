rule TTP_XOR_MULT_DOSStub_b875 {
  strings:
    $key_b875 = { ec 1d [2] 98 05 [2] df 07 [2] 98 16 [2] d6 1a [2] da 10 [2] cd 1b [2] d6 55 [2] eb }

  condition:
    any of them
}