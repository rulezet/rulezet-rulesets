rule TTP_XOR_MULT_DOSStub_b86a {
  strings:
    $key_b86a = { ec 02 [2] 98 1a [2] df 18 [2] 98 09 [2] d6 05 [2] da 0f [2] cd 04 [2] d6 4a [2] eb }

  condition:
    any of them
}