rule TTP_XOR_MULT_DOSStub_ed60 {
  strings:
    $key_ed60 = { b9 08 [2] cd 10 [2] 8a 12 [2] cd 03 [2] 83 0f [2] 8f 05 [2] 98 0e [2] 83 40 [2] be }

  condition:
    any of them
}