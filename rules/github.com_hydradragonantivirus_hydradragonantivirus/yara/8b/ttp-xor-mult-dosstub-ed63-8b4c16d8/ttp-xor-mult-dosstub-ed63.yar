rule TTP_XOR_MULT_DOSStub_ed63 {
  strings:
    $key_ed63 = { b9 0b [2] cd 13 [2] 8a 11 [2] cd 00 [2] 83 0c [2] 8f 06 [2] 98 0d [2] 83 43 [2] be }

  condition:
    any of them
}