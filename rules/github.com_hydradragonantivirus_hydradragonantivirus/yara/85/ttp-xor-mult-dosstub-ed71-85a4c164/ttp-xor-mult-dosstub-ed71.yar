rule TTP_XOR_MULT_DOSStub_ed71 {
  strings:
    $key_ed71 = { b9 19 [2] cd 01 [2] 8a 03 [2] cd 12 [2] 83 1e [2] 8f 14 [2] 98 1f [2] 83 51 [2] be }

  condition:
    any of them
}