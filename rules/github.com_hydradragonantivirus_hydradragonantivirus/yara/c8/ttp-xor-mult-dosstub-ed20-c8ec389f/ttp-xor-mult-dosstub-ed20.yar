rule TTP_XOR_MULT_DOSStub_ed20 {
  strings:
    $key_ed20 = { b9 48 [2] cd 50 [2] 8a 52 [2] cd 43 [2] 83 4f [2] 8f 45 [2] 98 4e [2] 83 00 [2] be }

  condition:
    any of them
}