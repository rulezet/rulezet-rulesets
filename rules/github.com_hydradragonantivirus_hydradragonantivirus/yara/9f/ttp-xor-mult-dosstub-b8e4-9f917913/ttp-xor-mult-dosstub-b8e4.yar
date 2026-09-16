rule TTP_XOR_MULT_DOSStub_b8e4 {
  strings:
    $key_b8e4 = { ec 8c [2] 98 94 [2] df 96 [2] 98 87 [2] d6 8b [2] da 81 [2] cd 8a [2] d6 c4 [2] eb }

  condition:
    any of them
}