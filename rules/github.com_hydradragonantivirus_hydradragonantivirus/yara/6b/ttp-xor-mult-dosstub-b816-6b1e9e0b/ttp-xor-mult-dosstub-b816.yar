rule TTP_XOR_MULT_DOSStub_b816 {
  strings:
    $key_b816 = { ec 7e [2] 98 66 [2] df 64 [2] 98 75 [2] d6 79 [2] da 73 [2] cd 78 [2] d6 36 [2] eb }

  condition:
    any of them
}