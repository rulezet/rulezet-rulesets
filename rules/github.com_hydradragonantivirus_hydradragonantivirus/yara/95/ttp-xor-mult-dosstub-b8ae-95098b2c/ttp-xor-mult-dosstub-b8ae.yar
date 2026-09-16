rule TTP_XOR_MULT_DOSStub_b8ae {
  strings:
    $key_b8ae = { ec c6 [2] 98 de [2] df dc [2] 98 cd [2] d6 c1 [2] da cb [2] cd c0 [2] d6 8e [2] eb }

  condition:
    any of them
}