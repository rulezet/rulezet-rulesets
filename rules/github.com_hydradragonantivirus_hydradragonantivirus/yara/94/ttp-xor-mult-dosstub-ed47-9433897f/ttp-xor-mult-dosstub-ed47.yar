rule TTP_XOR_MULT_DOSStub_ed47 {
  strings:
    $key_ed47 = { b9 2f [2] cd 37 [2] 8a 35 [2] cd 24 [2] 83 28 [2] 8f 22 [2] 98 29 [2] 83 67 [2] be }

  condition:
    any of them
}