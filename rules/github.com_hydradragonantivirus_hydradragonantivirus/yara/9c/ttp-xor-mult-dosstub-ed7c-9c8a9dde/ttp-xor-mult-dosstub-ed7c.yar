rule TTP_XOR_MULT_DOSStub_ed7c {
  strings:
    $key_ed7c = { b9 14 [2] cd 0c [2] 8a 0e [2] cd 1f [2] 83 13 [2] 8f 19 [2] 98 12 [2] 83 5c [2] be }

  condition:
    any of them
}