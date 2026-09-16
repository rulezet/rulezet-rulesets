rule TTP_XOR_MULT_DOSStub_ede9 {
  strings:
    $key_ede9 = { b9 81 [2] cd 99 [2] 8a 9b [2] cd 8a [2] 83 86 [2] 8f 8c [2] 98 87 [2] 83 c9 [2] be }

  condition:
    any of them
}