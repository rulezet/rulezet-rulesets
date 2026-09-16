rule TTP_XOR_MULT_DOSStub_b81a {
  strings:
    $key_b81a = { ec 72 [2] 98 6a [2] df 68 [2] 98 79 [2] d6 75 [2] da 7f [2] cd 74 [2] d6 3a [2] eb }

  condition:
    any of them
}