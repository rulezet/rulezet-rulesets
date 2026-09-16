rule TTP_XOR_MULT_DOSStub_b8e1 {
  strings:
    $key_b8e1 = { ec 89 [2] 98 91 [2] df 93 [2] 98 82 [2] d6 8e [2] da 84 [2] cd 8f [2] d6 c1 [2] eb }

  condition:
    any of them
}