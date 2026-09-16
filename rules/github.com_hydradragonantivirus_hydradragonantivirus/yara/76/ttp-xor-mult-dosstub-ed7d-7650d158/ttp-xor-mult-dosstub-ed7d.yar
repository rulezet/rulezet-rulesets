rule TTP_XOR_MULT_DOSStub_ed7d {
  strings:
    $key_ed7d = { b9 15 [2] cd 0d [2] 8a 0f [2] cd 1e [2] 83 12 [2] 8f 18 [2] 98 13 [2] 83 5d [2] be }

  condition:
    any of them
}