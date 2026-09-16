rule TTP_XOR_MULT_DOSStub_ed74 {
  strings:
    $key_ed74 = { b9 1c [2] cd 04 [2] 8a 06 [2] cd 17 [2] 83 1b [2] 8f 11 [2] 98 1a [2] 83 54 [2] be }

  condition:
    any of them
}