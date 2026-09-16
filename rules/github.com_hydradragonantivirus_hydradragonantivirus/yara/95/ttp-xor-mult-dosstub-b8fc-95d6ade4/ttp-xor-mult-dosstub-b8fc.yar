rule TTP_XOR_MULT_DOSStub_b8fc {
  strings:
    $key_b8fc = { ec 94 [2] 98 8c [2] df 8e [2] 98 9f [2] d6 93 [2] da 99 [2] cd 92 [2] d6 dc [2] eb }

  condition:
    any of them
}