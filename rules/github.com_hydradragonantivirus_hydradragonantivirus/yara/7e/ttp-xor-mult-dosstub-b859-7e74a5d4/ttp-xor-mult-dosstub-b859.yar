rule TTP_XOR_MULT_DOSStub_b859 {
  strings:
    $key_b859 = { ec 31 [2] 98 29 [2] df 2b [2] 98 3a [2] d6 36 [2] da 3c [2] cd 37 [2] d6 79 [2] eb }

  condition:
    any of them
}