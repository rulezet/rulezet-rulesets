rule TTP_XOR_MULT_DOSStub_b888 {
  strings:
    $key_b888 = { ec e0 [2] 98 f8 [2] df fa [2] 98 eb [2] d6 e7 [2] da ed [2] cd e6 [2] d6 a8 [2] eb }

  condition:
    any of them
}