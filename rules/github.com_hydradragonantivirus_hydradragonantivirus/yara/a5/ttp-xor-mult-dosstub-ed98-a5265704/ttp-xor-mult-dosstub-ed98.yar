rule TTP_XOR_MULT_DOSStub_ed98 {
  strings:
    $key_ed98 = { b9 f0 [2] cd e8 [2] 8a ea [2] cd fb [2] 83 f7 [2] 8f fd [2] 98 f6 [2] 83 b8 [2] be }

  condition:
    any of them
}