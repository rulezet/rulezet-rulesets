rule TTP_XOR_MULT_DOSStub_ed44 {
  strings:
    $key_ed44 = { b9 2c [2] cd 34 [2] 8a 36 [2] cd 27 [2] 83 2b [2] 8f 21 [2] 98 2a [2] 83 64 [2] be }

  condition:
    any of them
}