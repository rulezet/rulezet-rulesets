rule TTP_XOR_MULT_DOSStub_ed07 {
  strings:
    $key_ed07 = { b9 6f [2] cd 77 [2] 8a 75 [2] cd 64 [2] 83 68 [2] 8f 62 [2] 98 69 [2] 83 27 [2] be }

  condition:
    any of them
}