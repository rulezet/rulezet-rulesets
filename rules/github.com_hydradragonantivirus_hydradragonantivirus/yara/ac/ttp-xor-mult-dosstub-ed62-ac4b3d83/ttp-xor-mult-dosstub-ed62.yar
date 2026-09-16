rule TTP_XOR_MULT_DOSStub_ed62 {
  strings:
    $key_ed62 = { b9 0a [2] cd 12 [2] 8a 10 [2] cd 01 [2] 83 0d [2] 8f 07 [2] 98 0c [2] 83 42 [2] be }

  condition:
    any of them
}