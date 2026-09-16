rule TTP_XOR_MULT_DOSStub_b8b8 {
  strings:
    $key_b8b8 = { ec d0 [2] 98 c8 [2] df ca [2] 98 db [2] d6 d7 [2] da dd [2] cd d6 [2] d6 98 [2] eb }

  condition:
    any of them
}