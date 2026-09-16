rule TTP_XOR_MULT_DOSStub_ed4b {
  strings:
    $key_ed4b = { b9 23 [2] cd 3b [2] 8a 39 [2] cd 28 [2] 83 24 [2] 8f 2e [2] 98 25 [2] 83 6b [2] be }

  condition:
    any of them
}