rule TTP_XOR_MULT_DOSStub_ede1 {
  strings:
    $key_ede1 = { b9 89 [2] cd 91 [2] 8a 93 [2] cd 82 [2] 83 8e [2] 8f 84 [2] 98 8f [2] 83 c1 [2] be }

  condition:
    any of them
}