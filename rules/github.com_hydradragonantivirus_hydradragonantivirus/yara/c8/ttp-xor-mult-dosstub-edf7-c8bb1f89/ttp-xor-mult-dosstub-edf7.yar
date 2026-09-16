rule TTP_XOR_MULT_DOSStub_edf7 {
  strings:
    $key_edf7 = { b9 9f [2] cd 87 [2] 8a 85 [2] cd 94 [2] 83 98 [2] 8f 92 [2] 98 99 [2] 83 d7 [2] be }

  condition:
    any of them
}