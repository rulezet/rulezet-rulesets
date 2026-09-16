rule TTP_XOR_MULT_DOSStub_ed22 {
  strings:
    $key_ed22 = { b9 4a [2] cd 52 [2] 8a 50 [2] cd 41 [2] 83 4d [2] 8f 47 [2] 98 4c [2] 83 02 [2] be }

  condition:
    any of them
}