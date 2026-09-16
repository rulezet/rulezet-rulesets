rule TTP_XOR_MULT_DOSStub_ed7b {
  strings:
    $key_ed7b = { b9 13 [2] cd 0b [2] 8a 09 [2] cd 18 [2] 83 14 [2] 8f 1e [2] 98 15 [2] 83 5b [2] be }

  condition:
    any of them
}