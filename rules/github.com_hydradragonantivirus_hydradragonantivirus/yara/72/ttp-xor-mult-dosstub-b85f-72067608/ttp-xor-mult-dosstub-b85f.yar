rule TTP_XOR_MULT_DOSStub_b85f {
  strings:
    $key_b85f = { ec 37 [2] 98 2f [2] df 2d [2] 98 3c [2] d6 30 [2] da 3a [2] cd 31 [2] d6 7f [2] eb }

  condition:
    any of them
}