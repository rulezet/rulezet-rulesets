rule TTP_XOR_MULT_DOSStub_ed3e {
  strings:
    $key_ed3e = { b9 56 [2] cd 4e [2] 8a 4c [2] cd 5d [2] 83 51 [2] 8f 5b [2] 98 50 [2] 83 1e [2] be }

  condition:
    any of them
}