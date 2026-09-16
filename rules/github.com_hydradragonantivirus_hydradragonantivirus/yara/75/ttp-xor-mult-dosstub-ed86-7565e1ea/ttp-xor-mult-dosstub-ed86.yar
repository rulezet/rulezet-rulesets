rule TTP_XOR_MULT_DOSStub_ed86 {
  strings:
    $key_ed86 = { b9 ee [2] cd f6 [2] 8a f4 [2] cd e5 [2] 83 e9 [2] 8f e3 [2] 98 e8 [2] 83 a6 [2] be }

  condition:
    any of them
}