rule TTP_XOR_MULT_DOSStub_ed2c {
  strings:
    $key_ed2c = { b9 44 [2] cd 5c [2] 8a 5e [2] cd 4f [2] 83 43 [2] 8f 49 [2] 98 42 [2] 83 0c [2] be }

  condition:
    any of them
}