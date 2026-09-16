rule TTP_XOR_MULT_DOSStub_ed31 {
  strings:
    $key_ed31 = { b9 59 [2] cd 41 [2] 8a 43 [2] cd 52 [2] 83 5e [2] 8f 54 [2] 98 5f [2] 83 11 [2] be }

  condition:
    any of them
}