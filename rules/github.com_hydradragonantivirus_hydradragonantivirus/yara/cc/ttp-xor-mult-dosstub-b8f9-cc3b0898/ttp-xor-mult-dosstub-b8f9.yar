rule TTP_XOR_MULT_DOSStub_b8f9 {
  strings:
    $key_b8f9 = { ec 91 [2] 98 89 [2] df 8b [2] 98 9a [2] d6 96 [2] da 9c [2] cd 97 [2] d6 d9 [2] eb }

  condition:
    any of them
}