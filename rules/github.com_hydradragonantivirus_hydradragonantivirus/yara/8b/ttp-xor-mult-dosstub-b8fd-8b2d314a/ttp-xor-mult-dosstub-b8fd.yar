rule TTP_XOR_MULT_DOSStub_b8fd {
  strings:
    $key_b8fd = { ec 95 [2] 98 8d [2] df 8f [2] 98 9e [2] d6 92 [2] da 98 [2] cd 93 [2] d6 dd [2] eb }

  condition:
    any of them
}