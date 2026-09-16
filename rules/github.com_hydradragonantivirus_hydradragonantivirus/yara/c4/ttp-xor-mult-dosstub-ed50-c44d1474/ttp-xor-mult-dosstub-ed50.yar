rule TTP_XOR_MULT_DOSStub_ed50 {
  strings:
    $key_ed50 = { b9 38 [2] cd 20 [2] 8a 22 [2] cd 33 [2] 83 3f [2] 8f 35 [2] 98 3e [2] 83 70 [2] be }

  condition:
    any of them
}