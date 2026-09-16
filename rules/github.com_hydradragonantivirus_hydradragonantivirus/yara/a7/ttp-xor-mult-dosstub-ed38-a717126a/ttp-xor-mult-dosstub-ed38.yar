rule TTP_XOR_MULT_DOSStub_ed38 {
  strings:
    $key_ed38 = { b9 50 [2] cd 48 [2] 8a 4a [2] cd 5b [2] 83 57 [2] 8f 5d [2] 98 56 [2] 83 18 [2] be }

  condition:
    any of them
}