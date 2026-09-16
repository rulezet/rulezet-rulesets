rule TTP_XOR_MULT_DOSStub_ed36 {
  strings:
    $key_ed36 = { b9 5e [2] cd 46 [2] 8a 44 [2] cd 55 [2] 83 59 [2] 8f 53 [2] 98 58 [2] 83 16 [2] be }

  condition:
    any of them
}