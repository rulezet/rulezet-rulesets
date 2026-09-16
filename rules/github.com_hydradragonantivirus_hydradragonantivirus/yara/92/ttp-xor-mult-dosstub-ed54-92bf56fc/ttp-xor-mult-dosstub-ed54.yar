rule TTP_XOR_MULT_DOSStub_ed54 {
  strings:
    $key_ed54 = { b9 3c [2] cd 24 [2] 8a 26 [2] cd 37 [2] 83 3b [2] 8f 31 [2] 98 3a [2] 83 74 [2] be }

  condition:
    any of them
}