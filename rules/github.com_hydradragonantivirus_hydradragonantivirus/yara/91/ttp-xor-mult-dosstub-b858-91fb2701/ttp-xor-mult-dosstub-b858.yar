rule TTP_XOR_MULT_DOSStub_b858 {
  strings:
    $key_b858 = { ec 30 [2] 98 28 [2] df 2a [2] 98 3b [2] d6 37 [2] da 3d [2] cd 36 [2] d6 78 [2] eb }

  condition:
    any of them
}