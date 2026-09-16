rule TTP_XOR_MULT_DOSStub_ed61 {
  strings:
    $key_ed61 = { b9 09 [2] cd 11 [2] 8a 13 [2] cd 02 [2] 83 0e [2] 8f 04 [2] 98 0f [2] 83 41 [2] be }

  condition:
    any of them
}