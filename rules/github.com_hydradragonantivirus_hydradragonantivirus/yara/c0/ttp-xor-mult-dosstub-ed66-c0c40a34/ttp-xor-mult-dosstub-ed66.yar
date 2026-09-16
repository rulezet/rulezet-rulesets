rule TTP_XOR_MULT_DOSStub_ed66 {
  strings:
    $key_ed66 = { b9 0e [2] cd 16 [2] 8a 14 [2] cd 05 [2] 83 09 [2] 8f 03 [2] 98 08 [2] 83 46 [2] be }

  condition:
    any of them
}