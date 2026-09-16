rule TTP_XOR_MULT_DOSStub_ed6e {
  strings:
    $key_ed6e = { b9 06 [2] cd 1e [2] 8a 1c [2] cd 0d [2] 83 01 [2] 8f 0b [2] 98 00 [2] 83 4e [2] be }

  condition:
    any of them
}