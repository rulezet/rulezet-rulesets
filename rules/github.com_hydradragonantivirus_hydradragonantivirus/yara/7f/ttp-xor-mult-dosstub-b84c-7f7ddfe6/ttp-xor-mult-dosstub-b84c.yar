rule TTP_XOR_MULT_DOSStub_b84c {
  strings:
    $key_b84c = { ec 24 [2] 98 3c [2] df 3e [2] 98 2f [2] d6 23 [2] da 29 [2] cd 22 [2] d6 6c [2] eb }

  condition:
    any of them
}