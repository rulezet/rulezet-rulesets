rule TTP_XOR_MULT_DOSStub_ed48 {
  strings:
    $key_ed48 = { b9 20 [2] cd 38 [2] 8a 3a [2] cd 2b [2] 83 27 [2] 8f 2d [2] 98 26 [2] 83 68 [2] be }

  condition:
    any of them
}