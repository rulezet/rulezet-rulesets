rule TTP_XOR_MULT_DOSStub_ed78 {
  strings:
    $key_ed78 = { b9 10 [2] cd 08 [2] 8a 0a [2] cd 1b [2] 83 17 [2] 8f 1d [2] 98 16 [2] 83 58 [2] be }

  condition:
    any of them
}