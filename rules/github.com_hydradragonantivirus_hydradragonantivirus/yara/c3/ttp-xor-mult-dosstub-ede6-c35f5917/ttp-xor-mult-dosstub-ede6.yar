rule TTP_XOR_MULT_DOSStub_ede6 {
  strings:
    $key_ede6 = { b9 8e [2] cd 96 [2] 8a 94 [2] cd 85 [2] 83 89 [2] 8f 83 [2] 98 88 [2] 83 c6 [2] be }

  condition:
    any of them
}