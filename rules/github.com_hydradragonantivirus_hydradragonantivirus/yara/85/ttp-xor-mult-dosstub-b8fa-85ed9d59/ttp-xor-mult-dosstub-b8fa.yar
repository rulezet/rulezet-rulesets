rule TTP_XOR_MULT_DOSStub_b8fa {
  strings:
    $key_b8fa = { ec 92 [2] 98 8a [2] df 88 [2] 98 99 [2] d6 95 [2] da 9f [2] cd 94 [2] d6 da [2] eb }

  condition:
    any of them
}