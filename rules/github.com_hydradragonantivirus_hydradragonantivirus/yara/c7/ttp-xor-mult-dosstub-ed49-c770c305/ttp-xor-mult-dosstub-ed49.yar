rule TTP_XOR_MULT_DOSStub_ed49 {
  strings:
    $key_ed49 = { b9 21 [2] cd 39 [2] 8a 3b [2] cd 2a [2] 83 26 [2] 8f 2c [2] 98 27 [2] 83 69 [2] be }

  condition:
    any of them
}