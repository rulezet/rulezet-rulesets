rule TTP_XOR_MULT_DOSStub_ed00 {
  strings:
    $key_ed00 = { b9 68 [2] cd 70 [2] 8a 72 [2] cd 63 [2] 83 6f [2] 8f 65 [2] 98 6e [2] 83 20 [2] be }

  condition:
    any of them
}