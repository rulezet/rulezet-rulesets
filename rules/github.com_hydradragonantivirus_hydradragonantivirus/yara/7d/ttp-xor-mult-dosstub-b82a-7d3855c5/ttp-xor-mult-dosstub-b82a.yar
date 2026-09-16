rule TTP_XOR_MULT_DOSStub_b82a {
  strings:
    $key_b82a = { ec 42 [2] 98 5a [2] df 58 [2] 98 49 [2] d6 45 [2] da 4f [2] cd 44 [2] d6 0a [2] eb }

  condition:
    any of them
}